"""
SentinelPay – Payment state machine (Phase 8).

Enforces legal state transitions and records a PaymentEvent for each move.
Every transition is guarded: illegal moves raise IllegalTransition.

Allowed transitions:
  PROCESSING → SETTLED | FAILED | UNKNOWN
  UNKNOWN    → SETTLED | FAILED | NEEDS_INVESTIGATION
  FAILED     → REVERSED
  SETTLED    → NEEDS_INVESTIGATION
  Everything else is illegal.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.payments.models import Payment, PaymentEvent, PaymentStatus


class IllegalTransition(Exception):
    """Raised when a payment state transition violates the state machine rules."""

    def __init__(self, from_status: PaymentStatus, to_status: PaymentStatus) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Illegal state transition: {from_status.value} → {to_status.value}"
        )


# Legal transitions: {current_status: set(allowed_next_statuses)}
ALLOWED_TRANSITIONS: dict[PaymentStatus, set[PaymentStatus]] = {
    PaymentStatus.PROCESSING: {
        PaymentStatus.SETTLED,
        PaymentStatus.FAILED,
        PaymentStatus.UNKNOWN,
    },
    PaymentStatus.UNKNOWN: {
        PaymentStatus.SETTLED,
        PaymentStatus.FAILED,
        PaymentStatus.NEEDS_INVESTIGATION,
    },
    PaymentStatus.FAILED: {
        PaymentStatus.REVERSED,
    },
    PaymentStatus.SETTLED: {
        PaymentStatus.NEEDS_INVESTIGATION,
    },
    PaymentStatus.REVERSED: {
        PaymentStatus.NEEDS_INVESTIGATION,
    },
    PaymentStatus.NEEDS_INVESTIGATION: set(),
}


def transition(
    db: Session,
    payment: Payment,
    new_status: PaymentStatus,
    note: str | None = None,
) -> PaymentEvent:
    """Transition a payment to a new status.

    1. Validates the transition is legal.
    2. Updates the payment status and updated_at.
    3. Creates a PaymentEvent in the SAME transaction (caller commits).
    4. Returns the PaymentEvent.

    Raises IllegalTransition if the move is not allowed.
    """
    current = payment.status
    allowed = ALLOWED_TRANSITIONS.get(current, set())

    if new_status not in allowed:
        raise IllegalTransition(current, new_status)

    now_utc = datetime.now(timezone.utc)

    event = PaymentEvent(
        payment_id=payment.id,
        from_status=current.value,
        to_status=new_status.value,
        note=note,
        created_at=now_utc,
    )
    db.add(event)

    payment.status = new_status
    payment.updated_at = now_utc

    db.flush()
    return event
