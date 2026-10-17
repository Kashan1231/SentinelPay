"""
SentinelPay – Payment service layer (Phase 8).

Implements the 3-step bill payment pattern:
  Step 1: Debit sender, create PROCESSING payment, COMMIT.
  Step 2: Call the external rail AFTER commit (no DB transaction or row lock held).
  Step 3: Apply the outcome in a NEW transaction.

WHY the rail call happens outside the DB transaction:
  Holding a DB transaction and row locks open while waiting for an external
  network call is dangerous.  If the biller is slow or down, the locks would
  block other users from touching their accounts.  By committing first, we
  release all locks immediately.  If the server crashes between step 1 and 3,
  the payment is left in PROCESSING and the sweep job recovers it later.
"""

import hashlib
import random
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.accounts.models import Account, AccountStatus
from app.audit.service import record_event, record_event_independent
from app.auth.models import User
from app.core.config import settings
from app.core.database import SessionLocal
from app.payments.models import Payment, PaymentStatus
from app.payments.schemas import PaymentCreate
from app.payments.state_machine import transition
from app.rail.client import MockRailClient, RailStatus, RailTimeout
from app.transactions.models import IdempotencyKey, Transaction, TransactionStatus


def _compute_payment_request_hash(payload: PaymentCreate) -> str:
    """Compute a deterministic SHA-256 hash of the payment request payload."""
    payload_json = payload.model_dump_json()
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def _generate_payment_ref(db: Session) -> str:
    """Generate a unique human-readable payment reference (e.g. PAY-A1B2C3D4E5F6)."""
    while True:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
        ref = f"PAY-{suffix}"
        stmt = select(Payment).where(Payment.payment_ref == ref)
        if db.scalar(stmt) is None:
            return ref


def _generate_rail_reference(db: Session) -> str:
    """Generate a unique rail reference (e.g. RAIL-A1B2C3D4E5F6)."""
    while True:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
        ref = f"RAIL-{suffix}"
        stmt = select(Payment).where(Payment.rail_reference == ref)
        if db.scalar(stmt) is None:
            return ref


def initiate_payment(
    db: Session,
    current_user: User,
    payload: PaymentCreate,
    idempotency_key: str,
    ip_address: str | None = None,
) -> dict:
    """Execute the full 3-step bill payment flow.

    Returns a dict suitable for JSON response serialization.
    """
    request_hash = _compute_payment_request_hash(payload)

    # ── IDEMPOTENCY CHECK (FAST PATH) ─────────────────────────
    stmt_key = select(IdempotencyKey).where(
        IdempotencyKey.idempotency_key == idempotency_key,
        IdempotencyKey.user_id == current_user.id,
    )
    existing_key = db.scalar(stmt_key)
    if existing_key is not None:
        if existing_key.request_hash != request_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key reused with a different request",
            )
        record_event_independent(
            event_type="IDEMPOTENT_REPLAY",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="payment",
            entity_id=str(existing_key.response_body.get("id", "")),
            outcome="SUCCESS",
            details={"idempotency_key": idempotency_key},
            ip_address=ip_address,
            db=db,
        )
        return existing_key.response_body

    # ── VALIDATE SENDER ACCOUNT ─────────────────────────────
    if payload.sender_account_id is not None:
        sender_account = db.get(Account, payload.sender_account_id)
        if not sender_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sender account not found",
            )
        if sender_account.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Sender account does not belong to the current user",
            )
    else:
        stmt = select(Account).where(Account.user_id == current_user.id)
        user_accounts = db.scalars(stmt).all()
        if not user_accounts:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No bank account found for current user",
            )
        active_accounts = [acc for acc in user_accounts if acc.status == AccountStatus.ACTIVE]
        if not active_accounts:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Sender account is not active",
            )
        if len(active_accounts) > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Multiple bank accounts found. Please specify sender_account_id",
            )
        sender_account = active_accounts[0]

    if sender_account.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sender account is not active",
        )

    # ── TRANSACTION LIMITS (reuse existing thresholds) ─────────
    if payload.amount > settings.SINGLE_TRANSFER_LIMIT:
        record_event_independent(
            event_type="PAYMENT_REJECTED_LIMIT",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="payment",
            entity_id=None,
            outcome="DENIED",
            details={
                "amount": str(payload.amount),
                "limit_type": "SINGLE_TRANSFER_LIMIT",
                "limit": str(settings.SINGLE_TRANSFER_LIMIT),
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Payment amount exceeds single transfer limit of {settings.SINGLE_TRANSFER_LIMIT}",
        )

    # Daily limit check (include both completed transactions and settled/processing payments)
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    daily_tx_sum_stmt = select(
        func.coalesce(func.sum(Transaction.amount), Decimal("0.00"))
    ).where(
        Transaction.sender_account_id == sender_account.id,
        Transaction.status == TransactionStatus.COMPLETED,
        Transaction.created_at >= cutoff_24h,
    )
    daily_pay_sum_stmt = select(
        func.coalesce(func.sum(Payment.amount), Decimal("0.00"))
    ).where(
        Payment.sender_account_id == sender_account.id,
        Payment.status.in_([PaymentStatus.PROCESSING, PaymentStatus.SETTLED]),
        Payment.created_at >= cutoff_24h,
    )
    daily_tx_total = db.scalar(daily_tx_sum_stmt) or Decimal("0.00")
    daily_pay_total = db.scalar(daily_pay_sum_stmt) or Decimal("0.00")
    daily_total = daily_tx_total + daily_pay_total

    if daily_total + payload.amount > settings.DAILY_TRANSFER_LIMIT:
        record_event_independent(
            event_type="PAYMENT_REJECTED_LIMIT",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="payment",
            entity_id=None,
            outcome="DENIED",
            details={
                "amount": str(payload.amount),
                "limit_type": "DAILY_TRANSFER_LIMIT",
                "limit": str(settings.DAILY_TRANSFER_LIMIT),
                "daily_total": str(daily_total),
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Payment exceeds daily transfer limit of {settings.DAILY_TRANSFER_LIMIT} (already used: {daily_total})",
        )

    # ───────────────────────────────────────────────────────────
    # STEP 1: DEBIT AND CREATE PROCESSING PAYMENT (ONE DB TRANSACTION)
    # ───────────────────────────────────────────────────────────

    # Lock the sender account to prevent concurrent balance races
    db.scalars(
        select(Account).where(Account.id == sender_account.id).with_for_update()
    ).first()
    sender_account = db.get(Account, sender_account.id)

    if sender_account.balance < payload.amount:
        record_event_independent(
            event_type="PAYMENT_FAILED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="payment",
            entity_id=None,
            outcome="FAILURE",
            details={"amount": str(payload.amount), "reason": "Insufficient funds"},
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient funds",
        )

    now_utc = datetime.now(timezone.utc)
    payment_ref = _generate_payment_ref(db)
    rail_reference = _generate_rail_reference(db)

    # Debit the sender
    sender_account.balance -= payload.amount

    payment = Payment(
        payment_ref=payment_ref,
        user_id=current_user.id,
        sender_account_id=sender_account.id,
        biller_code=payload.biller_code,
        amount=payload.amount,
        status=PaymentStatus.PROCESSING,
        rail_reference=rail_reference,
        attempts_count=0,
        created_at=now_utc,
        updated_at=now_utc,
    )
    db.add(payment)
    db.flush()

    # Record initial state event
    from app.payments.state_machine import PaymentEvent
    init_event = PaymentEvent(
        payment_id=payment.id,
        from_status=None,
        to_status=PaymentStatus.PROCESSING.value,
        note="Payment initiated, funds debited from sender.",
        created_at=now_utc,
    )
    db.add(init_event)

    record_event(
        db=db,
        event_type="PAYMENT_INITIATED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="payment",
        entity_id=str(payment.id),
        outcome="SUCCESS",
        details={
            "payment_ref": payment_ref,
            "biller_code": payload.biller_code,
            "amount": str(payload.amount),
            "rail_reference": rail_reference,
        },
        ip_address=ip_address,
    )

    # Build idempotency response
    from app.payments.schemas import CUSTOMER_STATUS_MESSAGES
    response_dict = {
        "id": payment.id,
        "payment_ref": payment.payment_ref,
        "sender_account_id": payment.sender_account_id,
        "biller_code": payment.biller_code,
        "amount": str(payment.amount),
        "status": payment.status.value,
        "status_message": CUSTOMER_STATUS_MESSAGES.get(payment.status.value, ""),
        "created_at": payment.created_at.isoformat(),
        "updated_at": payment.updated_at.isoformat(),
        "timeline": [],
    }

    idempotency_record = IdempotencyKey(
        idempotency_key=idempotency_key,
        user_id=current_user.id,
        request_hash=request_hash,
        response_status_code=status.HTTP_201_CREATED,
        response_body=response_dict,
        created_at=now_utc,
    )
    db.add(idempotency_record)
    db.commit()  # COMMIT Step 1 — releases all locks

    # ───────────────────────────────────────────────────────────
    # STEP 2: CALL THE EXTERNAL RAIL (NO DB TRANSACTION HELD)
    # ───────────────────────────────────────────────────────────
    # This is intentionally outside any DB transaction.  If the server crashes
    # here, the payment is left in PROCESSING and the sweep job picks it up.
    # This is exactly the "money deducted, bill unpaid" situation we want
    # to be able to reproduce and recover from.

    rail_session = SessionLocal()
    rail_client = MockRailClient(rail_session)
    rail_outcome = None
    rail_timeout = False

    try:
        result = rail_client.submit_payment(
            rail_reference=rail_reference,
            biller_code=payload.biller_code,
            amount=payload.amount,
        )
        rail_outcome = result.status
    except RailTimeout:
        rail_timeout = True
    except Exception:
        rail_timeout = True  # Treat unexpected errors as timeouts
    finally:
        rail_session.close()

    # ───────────────────────────────────────────────────────────
    # STEP 3: APPLY OUTCOME IN A NEW TRANSACTION
    # ───────────────────────────────────────────────────────────

    outcome_session = SessionLocal()
    try:
        # Lock the payment row first
        pay = outcome_session.scalar(
            select(Payment).where(Payment.id == payment.id).with_for_update()
        )

        if not pay or pay.status != PaymentStatus.PROCESSING:
            # Already resolved (e.g. by a concurrent sweep)
            outcome_session.close()
            return response_dict

        if rail_timeout:
            # UNKNOWN: We don't know if the biller processed it.
            transition(outcome_session, pay, PaymentStatus.UNKNOWN, "Rail call timed out. Outcome unknown.")
            record_event(
                db=outcome_session,
                event_type="PAYMENT_UNKNOWN",
                actor_user_id=current_user.id,
                actor_role=current_user.role.value,
                entity_type="payment",
                entity_id=str(pay.id),
                outcome="SUCCESS",
                details={
                    "payment_ref": pay.payment_ref,
                    "reason": "Rail timeout — outcome indeterminate",
                },
                ip_address=ip_address,
            )
            outcome_session.commit()

        elif rail_outcome == RailStatus.SETTLED:
            transition(outcome_session, pay, PaymentStatus.SETTLED, "Biller confirmed payment settled.")
            record_event(
                db=outcome_session,
                event_type="PAYMENT_SETTLED",
                actor_user_id=current_user.id,
                actor_role=current_user.role.value,
                entity_type="payment",
                entity_id=str(pay.id),
                outcome="SUCCESS",
                details={
                    "payment_ref": pay.payment_ref,
                    "amount": str(pay.amount),
                },
                ip_address=ip_address,
            )
            outcome_session.commit()

        elif rail_outcome == RailStatus.FAILED:
            transition(outcome_session, pay, PaymentStatus.FAILED, "Biller declined the payment.")
            pay.failure_reason = "Biller declined the payment"
            record_event(
                db=outcome_session,
                event_type="PAYMENT_FAILED",
                actor_user_id=current_user.id,
                actor_role=current_user.role.value,
                entity_type="payment",
                entity_id=str(pay.id),
                outcome="FAILURE",
                details={
                    "payment_ref": pay.payment_ref,
                    "reason": "Biller declined",
                },
                ip_address=ip_address,
            )
            outcome_session.flush()

            # Refund step: credit sender back
            _refund_payment(outcome_session, pay, current_user.id, current_user.role.value, ip_address)
            outcome_session.commit()

    except Exception:
        outcome_session.rollback()
        raise
    finally:
        outcome_session.close()

    # Re-read the final state
    db.refresh(payment)
    response_dict["status"] = payment.status.value
    response_dict["status_message"] = CUSTOMER_STATUS_MESSAGES.get(payment.status.value, "")
    response_dict["updated_at"] = payment.updated_at.isoformat()
    response_dict["timeline"] = [
        {
            "id": e.id,
            "from_status": e.from_status,
            "to_status": e.to_status,
            "note": e.note,
            "created_at": e.created_at.isoformat(),
        }
        for e in (payment.events or [])
    ]
    return response_dict


def _refund_payment(
    db: Session,
    payment: Payment,
    actor_user_id: int,
    actor_role: str,
    ip_address: str | None = None,
) -> None:
    """Credit the sender back exactly once.

    Guard against double refund by checking the status under a row lock.
    The transition FAILED → REVERSED enforces this at the state-machine level:
    if the payment is already REVERSED, the transition will raise IllegalTransition.
    """
    # Lock the sender account
    sender = db.scalar(
        select(Account).where(Account.id == payment.sender_account_id).with_for_update()
    )
    if not sender:
        return

    sender.balance += payment.amount

    transition(db, payment, PaymentStatus.REVERSED, "Payment reversed, funds credited back to sender.")

    record_event(
        db=db,
        event_type="PAYMENT_REVERSED",
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        entity_type="payment",
        entity_id=str(payment.id),
        outcome="SUCCESS",
        details={
            "payment_ref": payment.payment_ref,
            "amount": str(payment.amount),
            "refunded_to_account": sender.id,
        },
        ip_address=ip_address,
    )
