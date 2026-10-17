"""
SentinelPay – Payment recovery module (Phase 8).

resolve_unknown():       Status inquiry against the rail for a single payment.
sweep_stuck_payments():  Finds all stuck PROCESSING/UNKNOWN payments and resolves them.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.audit.service import record_event
from app.core.config import settings
from app.payments.models import Payment, PaymentStatus
from app.payments.state_machine import IllegalTransition, transition
from app.rail.client import MockRailClient, RailStatus


def resolve_unknown(
    db: Session,
    payment_id: int,
    ip_address: str | None = None,
) -> Payment:
    """Resolve a single UNKNOWN payment by querying the rail.

    Lock the payment row first, then call rail.get_status:
      - SETTLED   → transition UNKNOWN → SETTLED
      - FAILED    → transition UNKNOWN → FAILED → REVERSED (with refund)
      - NOT_FOUND → only after attempts_count >= PAYMENT_MAX_INQUIRIES treat as
                    failed and refund; before that, increment attempts_count,
                    set last_checked_at, stay UNKNOWN.
    """
    # Lock the payment row
    payment = db.scalar(
        select(Payment).where(Payment.id == payment_id).with_for_update()
    )
    if not payment:
        raise ValueError(f"Payment {payment_id} not found")

    if payment.status == PaymentStatus.REVERSED:
        return handle_late_settlement(db, payment.id, ip_address=ip_address)

    if payment.status not in (PaymentStatus.UNKNOWN, PaymentStatus.PROCESSING):
        return payment  # Already resolved

    # If still PROCESSING (crashed mid-flow), move to UNKNOWN first
    if payment.status == PaymentStatus.PROCESSING:
        transition(
            db, payment, PaymentStatus.UNKNOWN,
            "Recovery: payment was stuck in PROCESSING (server likely crashed mid-flow).",
        )
        record_event(
            db=db,
            event_type="PAYMENT_UNKNOWN",
            actor_user_id=None,
            actor_role="system",
            entity_type="payment",
            entity_id=str(payment.id),
            outcome="SUCCESS",
            details={
                "payment_ref": payment.payment_ref,
                "reason": "Stuck PROCESSING — moved to UNKNOWN by sweep",
            },
            ip_address=ip_address,
        )
        db.flush()

    # Query the rail
    rail_client = MockRailClient(db)
    rail_status = rail_client.get_status(payment.rail_reference)
    now_utc = datetime.now(timezone.utc)

    if rail_status == RailStatus.SETTLED:
        # Check if we already REVERSED this payment.
        # If so, the late SETTLED means NEEDS_INVESTIGATION.
        if payment.status == PaymentStatus.REVERSED:
            try:
                # REVERSED is terminal — this shouldn't happen via normal path
                # but handle it defensively
                pass
            except Exception:
                pass
        else:
            transition(db, payment, PaymentStatus.SETTLED, "Recovery: rail confirmed SETTLED.")
            record_event(
                db=db,
                event_type="PAYMENT_SETTLED",
                actor_user_id=None,
                actor_role="system",
                entity_type="payment",
                entity_id=str(payment.id),
                outcome="SUCCESS",
                details={
                    "payment_ref": payment.payment_ref,
                    "resolved_by": "sweep",
                },
                ip_address=ip_address,
            )

    elif rail_status == RailStatus.FAILED:
        transition(db, payment, PaymentStatus.FAILED, "Recovery: rail confirmed FAILED.")
        payment.failure_reason = "Biller confirmed payment failed"
        record_event(
            db=db,
            event_type="PAYMENT_FAILED",
            actor_user_id=None,
            actor_role="system",
            entity_type="payment",
            entity_id=str(payment.id),
            outcome="FAILURE",
            details={
                "payment_ref": payment.payment_ref,
                "resolved_by": "sweep",
            },
            ip_address=ip_address,
        )
        db.flush()

        # Refund
        _refund_payment_recovery(db, payment, ip_address)

    elif rail_status == RailStatus.NOT_FOUND:
        payment.attempts_count += 1
        payment.last_checked_at = now_utc

        max_inquiries = getattr(settings, "PAYMENT_MAX_INQUIRIES", 3)

        if payment.attempts_count >= max_inquiries:
            # Exhausted retries → treat as failed
            transition(db, payment, PaymentStatus.FAILED, f"Recovery: rail returned NOT_FOUND after {payment.attempts_count} attempts. Treating as failed.")
            payment.failure_reason = f"Rail returned NOT_FOUND after {payment.attempts_count} inquiries"
            record_event(
                db=db,
                event_type="PAYMENT_FAILED",
                actor_user_id=None,
                actor_role="system",
                entity_type="payment",
                entity_id=str(payment.id),
                outcome="FAILURE",
                details={
                    "payment_ref": payment.payment_ref,
                    "resolved_by": "sweep",
                    "attempts": payment.attempts_count,
                },
                ip_address=ip_address,
            )
            db.flush()
            _refund_payment_recovery(db, payment, ip_address)
        else:
            record_event(
                db=db,
                event_type="PAYMENT_INQUIRY_PENDING",
                actor_user_id=None,
                actor_role="system",
                entity_type="payment",
                entity_id=str(payment.id),
                outcome="SUCCESS",
                details={
                    "payment_ref": payment.payment_ref,
                    "attempts": payment.attempts_count,
                    "max_inquiries": max_inquiries,
                },
                ip_address=ip_address,
            )

    return payment


def _refund_payment_recovery(
    db: Session,
    payment: Payment,
    ip_address: str | None = None,
) -> None:
    """Credit the sender back exactly once during recovery.

    Guard against double refund via the state machine: FAILED → REVERSED
    is only allowed once; calling it again raises IllegalTransition.
    """
    sender = db.scalar(
        select(Account).where(Account.id == payment.sender_account_id).with_for_update()
    )
    if not sender:
        return

    sender.balance += payment.amount

    transition(db, payment, PaymentStatus.REVERSED, "Recovery: refund credited to sender account.")

    record_event(
        db=db,
        event_type="PAYMENT_REVERSED",
        actor_user_id=None,
        actor_role="system",
        entity_type="payment",
        entity_id=str(payment.id),
        outcome="SUCCESS",
        details={
            "payment_ref": payment.payment_ref,
            "amount": str(payment.amount),
            "refunded_to_account": sender.id,
            "resolved_by": "sweep",
        },
        ip_address=ip_address,
    )


def sweep_stuck_payments(db: Session, ip_address: str | None = None) -> dict:
    """Find payments stuck in PROCESSING or UNKNOWN longer than the configured
    threshold and attempt to resolve each one.

    A PROCESSING payment stuck past the threshold means the server crashed
    mid-flow (between Step 1 and Step 3), so we move it to UNKNOWN first,
    then resolve.

    Returns a summary dict with counts.
    """
    stuck_after = getattr(settings, "PAYMENT_STUCK_AFTER_SECONDS", 120)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stuck_after)

    stmt = (
        select(Payment)
        .where(
            Payment.status.in_([PaymentStatus.PROCESSING, PaymentStatus.UNKNOWN]),
            Payment.updated_at <= cutoff,
        )
        .with_for_update(skip_locked=True)  # Skip already-locked rows (concurrent sweep safety)
    )
    stuck_payments = list(db.scalars(stmt).all())

    results = {"found": len(stuck_payments), "resolved": 0, "errors": 0}

    for pay in stuck_payments:
        try:
            resolve_unknown(db, pay.id, ip_address=ip_address)
            db.commit()
            results["resolved"] += 1
        except Exception:
            db.rollback()
            results["errors"] += 1

    return results


def handle_late_settlement(
    db: Session,
    payment_id: int,
    ip_address: str | None = None,
) -> Payment:
    """Handle the case where the rail later reports SETTLED for a payment
    we already REVERSED.

    Transition to NEEDS_INVESTIGATION and write an audit event.
    Never auto-resolve this case — a human must decide.
    """
    payment = db.scalar(
        select(Payment).where(Payment.id == payment_id).with_for_update()
    )
    if not payment:
        raise ValueError(f"Payment {payment_id} not found")

    if payment.status != PaymentStatus.REVERSED:
        return payment

    # Check if rail now says SETTLED
    rail_client = MockRailClient(db)
    rail_status = rail_client.get_status(payment.rail_reference)

    if rail_status == RailStatus.SETTLED:
        transition(
            db,
            payment,
            PaymentStatus.NEEDS_INVESTIGATION,
            "Late SETTLED detected after REVERSED — requires human investigation.",
        )

        record_event(
            db=db,
            event_type="PAYMENT_NEEDS_INVESTIGATION",
            actor_user_id=None,
            actor_role="system",
            entity_type="payment",
            entity_id=str(payment.id),
            outcome="SUCCESS",
            details={
                "payment_ref": payment.payment_ref,
                "reason": "Rail reports SETTLED after we already REVERSED (refunded). Double-credit risk.",
                "amount": str(payment.amount),
            },
            ip_address=ip_address,
        )

    return payment
