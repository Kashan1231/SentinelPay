"""
SentinelPay – Dispute State Machine (Phase 9 - Part B).

Guarantees legal dispute workflow transitions and automatically records a
DisputeEvent in the same database transaction.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.disputes.models import Dispute, DisputeEvent, DisputeStatus


class IllegalDisputeTransition(Exception):
    """Raised when an illegal transition is attempted on a dispute."""

    def __init__(self, from_status: DisputeStatus, to_status: DisputeStatus) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Illegal dispute transition: {from_status.value} → {to_status.value}"
        )


ALLOWED_DISPUTE_TRANSITIONS: dict[DisputeStatus, set[DisputeStatus]] = {
    DisputeStatus.OPEN: {
        DisputeStatus.INVESTIGATING,
        DisputeStatus.AWAITING_CUSTOMER,
        DisputeStatus.ESCALATED,
        DisputeStatus.RESOLVED_REFUNDED,
        DisputeStatus.RESOLVED_REJECTED,
    },
    DisputeStatus.INVESTIGATING: {
        DisputeStatus.AWAITING_CUSTOMER,
        DisputeStatus.OPEN,
        DisputeStatus.ESCALATED,
        DisputeStatus.RESOLVED_REFUNDED,
        DisputeStatus.RESOLVED_REJECTED,
    },
    DisputeStatus.AWAITING_CUSTOMER: {
        DisputeStatus.INVESTIGATING,
        DisputeStatus.OPEN,
        DisputeStatus.ESCALATED,
        DisputeStatus.RESOLVED_REFUNDED,
        DisputeStatus.RESOLVED_REJECTED,
    },
    DisputeStatus.ESCALATED: {
        DisputeStatus.INVESTIGATING,
        DisputeStatus.AWAITING_CUSTOMER,
        DisputeStatus.RESOLVED_REFUNDED,
        DisputeStatus.RESOLVED_REJECTED,
    },
    # Terminal states
    DisputeStatus.RESOLVED_REFUNDED: set(),
    DisputeStatus.RESOLVED_REJECTED: set(),
}


def transition_dispute(
    db: Session,
    dispute: Dispute,
    new_status: DisputeStatus,
    actor_user_id: int | None,
    note: str | None = None,
    visible_to_customer: bool = True,
) -> DisputeEvent:
    """Transition a dispute to a new status.

    1. Validates the transition is legal.
    2. Updates status and updated_at.
    3. Adds a DisputeEvent to the database session.
    4. Flushes changes.
    """
    current = dispute.status
    allowed = ALLOWED_DISPUTE_TRANSITIONS.get(current, set())

    if new_status not in allowed:
        raise IllegalDisputeTransition(current, new_status)

    now_utc = datetime.now(timezone.utc)
    event = DisputeEvent(
        dispute_id=dispute.id,
        actor_user_id=actor_user_id,
        from_status=current.value,
        to_status=new_status.value,
        note=note,
        visible_to_customer=visible_to_customer,
        created_at=now_utc,
    )
    db.add(event)

    dispute.status = new_status
    dispute.updated_at = now_utc
    if new_status in (DisputeStatus.RESOLVED_REFUNDED, DisputeStatus.RESOLVED_REJECTED):
        dispute.resolved_at = now_utc
        dispute.resolution_note = note

    db.flush()
    return event
