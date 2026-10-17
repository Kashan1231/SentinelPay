import hashlib
import random
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.accounts.models import Account, AccountStatus
from app.auth.models import User
from app.audit.service import record_event, record_event_independent
from app.core.config import settings
from app.fraud.engine import evaluate_transaction
from app.fraud.models import AlertStatus, FraudAlert, RiskLevel
from app.transactions.models import IdempotencyKey, Transaction, TransactionStatus
from app.transactions.schemas import TransactionCreate, TransactionResponse


def compute_request_hash(payload: TransactionCreate) -> str:
    """Compute a deterministic SHA-256 hash of the JSON request payload."""
    payload_json = payload.model_dump_json()
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def generate_transaction_ref(db: Session) -> str:
    """Generate a unique human-readable transaction reference string (e.g., TX-A1B2C3D4E5F6)."""
    while True:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
        tx_ref = f"TX-{suffix}"
        stmt = select(Transaction).where(Transaction.transaction_ref == tx_ref)
        if db.scalar(stmt) is None:
            return tx_ref


def execute_transfer(
    db: Session,
    current_user: User,
    payload: TransactionCreate,
    idempotency_key: str,
    ip_address: str | None = None,
) -> dict:
    """
    Execute a money transfer between a sender account and a recipient account.

    ATOMICITY & CONCURRENCY GUARANTEES:
    1. Idempotency Key check: if the key has been processed for this user with an identical
       payload, return stored response immediately. If payload differs, raise 409 Conflict.
    2. Lock Ordering (Deadlock Prevention): acquire row locks on accounts in ascending
       order of account.id (min_id then max_id).
    3. Row-level locking (SELECT ... FOR UPDATE): prevents concurrent race conditions on balance.
    4. Atomic DB Transaction: debit sender, credit recipient, create ledger record, and store
       idempotency key inside a SINGLE database transaction block.
    """
    request_hash = compute_request_hash(payload)

    # ── 1. IDEMPOTENCY CHECK (FAST PATH) ────────────────────────
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
        # Log a lightweight IDEMPOTENT_REPLAY event without duplicating original audit entry
        tx_id_str = None
        if isinstance(existing_key.response_body, dict) and "id" in existing_key.response_body:
            tx_id_str = str(existing_key.response_body["id"])
        record_event_independent(
            event_type="IDEMPOTENT_REPLAY",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="transaction",
            entity_id=tx_id_str,
            outcome="SUCCESS",
            details={"idempotency_key": idempotency_key},
            ip_address=ip_address,
            db=db,
        )
        return existing_key.response_body

    # ── 2. LOOK UP & VALIDATE SENDER ACCOUNT ────────────────────
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

    # ── 3. LOOK UP & VALIDATE RECIPIENT ACCOUNT ────────────────
    stmt_rec = select(Account).where(Account.account_number == payload.recipient_account_number)
    recipient_account = db.scalar(stmt_rec)
    if not recipient_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient account not found",
        )

    if recipient_account.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recipient account is not active",
        )

    # ── 4. BUSINESS RULE VALIDATIONS ─────────────────────────────
    if sender_account.id == recipient_account.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot transfer money to the same account",
        )

    if payload.amount <= Decimal("0.00"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transfer amount must be greater than zero",
        )

    # ── 5. TRANSACTION LIMITS (PRE-SCORING CHECK) ────────────────
    # Single transfer limit
    if payload.amount > settings.SINGLE_TRANSFER_LIMIT:
        record_event_independent(
            event_type="TRANSFER_REJECTED_LIMIT",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="transaction",
            entity_id=None,
            outcome="DENIED",
            details={
                "amount": str(payload.amount),
                "limit_type": "SINGLE_TRANSFER_LIMIT",
                "limit": str(settings.SINGLE_TRANSFER_LIMIT),
                "reason": f"Transfer amount exceeds single transfer limit of {settings.SINGLE_TRANSFER_LIMIT}",
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transfer amount exceeds single transfer limit of {settings.SINGLE_TRANSFER_LIMIT}",
        )

    # 24-hour daily transfer limit
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    daily_sum_stmt = select(func.coalesce(func.sum(Transaction.amount), Decimal("0.00"))).where(
        Transaction.sender_account_id == sender_account.id,
        Transaction.status == TransactionStatus.COMPLETED,
        Transaction.created_at >= cutoff_24h,
    )
    daily_total = db.scalar(daily_sum_stmt) or Decimal("0.00")

    if daily_total + payload.amount > settings.DAILY_TRANSFER_LIMIT:
        record_event_independent(
            event_type="TRANSFER_REJECTED_LIMIT",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="transaction",
            entity_id=None,
            outcome="DENIED",
            details={
                "amount": str(payload.amount),
                "limit_type": "DAILY_TRANSFER_LIMIT",
                "limit": str(settings.DAILY_TRANSFER_LIMIT),
                "daily_total": str(daily_total),
                "reason": f"Transfer exceeds daily transfer limit of {settings.DAILY_TRANSFER_LIMIT}",
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transfer exceeds daily transfer limit of {settings.DAILY_TRANSFER_LIMIT} (already used: {daily_total})",
        )

    # ── 6. FRAUD RULE ENGINE EVALUATION ──────────────────────────
    eval_result = evaluate_transaction(db, sender_account, recipient_account, payload.amount)

    now_utc = datetime.now(timezone.utc)
    tx_ref = generate_transaction_ref(db)

    # ── 7. DECISION EXECUTION ────────────────────────────────────
    # HIGH RISK: HOLD, DON'T MOVE MONEY
    # Transaction enters PENDING_REVIEW; FraudAlert OPEN created; no money moves.
    if eval_result.risk_level == RiskLevel.HIGH:
        try:
            transaction = Transaction(
                transaction_ref=tx_ref,
                sender_account_id=sender_account.id,
                recipient_account_id=recipient_account.id,
                amount=payload.amount,
                status=TransactionStatus.PENDING_REVIEW,
                description=payload.description,
                risk_score=eval_result.risk_score,
                risk_level=eval_result.risk_level,
                created_at=now_utc,
                completed_at=None,
            )
            db.add(transaction)
            db.flush()

            fraud_alert = FraudAlert(
                transaction_id=transaction.id,
                risk_score=eval_result.risk_score,
                risk_level=eval_result.risk_level,
                triggered_rules=eval_result.triggered_rules,
                status=AlertStatus.OPEN,
                created_at=now_utc,
            )
            db.add(fraud_alert)

            # Record TRANSFER_HELD inside the same transaction as transaction/alert creation
            record_event(
                db=db,
                event_type="TRANSFER_HELD",
                actor_user_id=current_user.id,
                actor_role=current_user.role.value,
                entity_type="transaction",
                entity_id=str(transaction.id),
                outcome="SUCCESS",
                details={
                    "transaction_ref": transaction.transaction_ref,
                    "amount": str(transaction.amount),
                    "status": "PENDING_REVIEW",
                    "risk_score": eval_result.risk_score,
                    "risk_level": eval_result.risk_level.value,
                },
                ip_address=ip_address,
            )

            # Customer sees only generic message; NO risk score or rules exposed
            resp = TransactionResponse.model_validate(transaction)
            resp.message = "Transfer submitted and held for routine verification. No funds have been moved."
            response_dict = resp.model_dump(mode="json")

            idempotency_record = IdempotencyKey(
                idempotency_key=idempotency_key,
                user_id=current_user.id,
                request_hash=request_hash,
                response_status_code=status.HTTP_201_CREATED,
                response_body=response_dict,
                created_at=now_utc,
            )
            db.add(idempotency_record)
            db.commit()

            return response_dict

        except IntegrityError:
            db.rollback()
            existing_key = db.scalar(stmt_key)
            if existing_key is not None:
                if existing_key.request_hash != request_hash:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key reused with a different request",
                    )
                return existing_key.response_body
            raise
        except Exception:
            db.rollback()
            raise

    # LOW & MEDIUM RISK: EXECUTE TRANSFER UNDER ROW-LEVEL LOCKS
    first_id = min(sender_account.id, recipient_account.id)
    second_id = max(sender_account.id, recipient_account.id)

    # Execute SELECT ... FOR UPDATE row locks in deterministic order
    db.scalars(
        select(Account)
        .where(Account.id == first_id)
        .with_for_update()
    ).first()

    db.scalars(
        select(Account)
        .where(Account.id == second_id)
        .with_for_update()
    ).first()

    # Refresh sender & recipient accounts bound to this locked transaction
    sender_account = db.get(Account, sender_account.id)
    recipient_account = db.get(Account, recipient_account.id)

    if sender_account.balance < payload.amount:
        record_event_independent(
            event_type="TRANSFER_FAILED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="transaction",
            entity_id=None,
            outcome="FAILURE",
            details={
                "amount": str(payload.amount),
                "reason": "Insufficient funds",
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient funds",
        )

    try:
        # Debit sender & Credit recipient
        sender_account.balance -= payload.amount
        recipient_account.balance += payload.amount

        transaction = Transaction(
            transaction_ref=tx_ref,
            sender_account_id=sender_account.id,
            recipient_account_id=recipient_account.id,
            amount=payload.amount,
            status=TransactionStatus.COMPLETED,
            description=payload.description,
            risk_score=eval_result.risk_score,
            risk_level=eval_result.risk_level,
            created_at=now_utc,
            completed_at=now_utc,
        )
        db.add(transaction)
        db.flush()

        # MEDIUM risk also creates an alert with status OPEN for visibility
        if eval_result.risk_level == RiskLevel.MEDIUM:
            fraud_alert = FraudAlert(
                transaction_id=transaction.id,
                risk_score=eval_result.risk_score,
                risk_level=eval_result.risk_level,
                triggered_rules=eval_result.triggered_rules,
                status=AlertStatus.OPEN,
                created_at=now_utc,
            )
            db.add(fraud_alert)

        # Record TRANSFER_COMPLETED within the same transaction as balance movement
        record_event(
            db=db,
            event_type="TRANSFER_COMPLETED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="transaction",
            entity_id=str(transaction.id),
            outcome="SUCCESS",
            details={
                "transaction_ref": transaction.transaction_ref,
                "sender_account_id": sender_account.id,
                "recipient_account_id": recipient_account.id,
                "amount": str(transaction.amount),
                "risk_score": eval_result.risk_score,
                "risk_level": eval_result.risk_level.value,
            },
            ip_address=ip_address,
        )

        resp = TransactionResponse.model_validate(transaction)
        resp.message = "Transfer completed successfully."
        response_dict = resp.model_dump(mode="json")

        idempotency_record = IdempotencyKey(
            idempotency_key=idempotency_key,
            user_id=current_user.id,
            request_hash=request_hash,
            response_status_code=status.HTTP_201_CREATED,
            response_body=response_dict,
            created_at=now_utc,
        )
        db.add(idempotency_record)
        db.commit()

        return response_dict

    except IntegrityError:
        db.rollback()
        existing_key = db.scalar(stmt_key)
        if existing_key is not None:
            if existing_key.request_hash != request_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key reused with a different request",
                )
            return existing_key.response_body
        raise
    except Exception:
        db.rollback()
        raise

