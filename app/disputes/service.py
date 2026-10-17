"""
SentinelPay – Dispute & SLA Service Layer (Phase 9 - Part B).

Manages customer dispute cases, SLA deadlines, investigator assignments,
separation of duties enforcement, deterministic refund execution,
and automated escalation sweeps.
"""

import hashlib
import random
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.audit.service import record_event, record_event_independent
from app.auth.models import User, UserRole
from app.core.config import settings
from app.disputes.models import (
    Dispute,
    DisputeCategory,
    DisputeEvent,
    DisputeRefund,
    DisputeStatus,
)
from app.disputes.schemas import (
    DisputeCreate,
    DisputeCustomerResponse,
    DisputeEventResponse,
    DisputeStaffResponse,
)
from app.disputes.state_machine import IllegalDisputeTransition, transition_dispute
from app.payments.models import Payment, PaymentStatus
from app.recon.models import ExceptionStatus, ReconciliationException
from app.transactions.models import IdempotencyKey, Transaction


def _generate_case_ref(db: Session) -> str:
    """Generate a unique human-readable dispute reference (e.g. DSP-A1B2C3D4E5F6)."""
    while True:
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
        ref = f"DSP-{suffix}"
        stmt = select(Dispute).where(Dispute.case_ref == ref)
        if db.scalar(stmt) is None:
            return ref


def _get_sla_seconds(category: DisputeCategory) -> int:
    """Determine SLA window in seconds based on category."""
    if category == DisputeCategory.DUPLICATE_DEBIT:
        return getattr(settings, "DISPUTE_SLA_SECONDS_DUPLICATE_DEBIT", 86400)
    elif category == DisputeCategory.PAID_BUT_NOT_CREDITED:
        return getattr(settings, "DISPUTE_SLA_SECONDS_PAID_NOT_CREDITED", 172800)
    elif category == DisputeCategory.UNAUTHORIZED:
        return getattr(settings, "DISPUTE_SLA_SECONDS_UNAUTHORIZED", 86400)
    return getattr(settings, "DISPUTE_SLA_SECONDS_OTHER", 259200)


def create_dispute(
    db: Session,
    current_user: User,
    payload: DisputeCreate,
    idempotency_key: str,
    ip_address: str | None = None,
) -> dict:
    """Customer initiates a dispute on their own payment or transaction."""
    payload_hash = hashlib.sha256(payload.model_dump_json().encode("utf-8")).hexdigest()

    # 1. Idempotency Check
    stmt_key = select(IdempotencyKey).where(
        IdempotencyKey.idempotency_key == idempotency_key,
        IdempotencyKey.user_id == current_user.id,
    )
    existing_key = db.scalar(stmt_key)
    if existing_key is not None:
        if existing_key.request_hash != payload_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key reused with a different request payload",
            )
        record_event_independent(
            event_type="IDEMPOTENT_REPLAY",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="dispute",
            entity_id=str(existing_key.response_body.get("id", "")),
            outcome="SUCCESS",
            details={"idempotency_key": idempotency_key},
            ip_address=ip_address,
            db=db,
        )
        return existing_key.response_body

    # 2. Validate Target Ownership
    if not payload.payment_id and not payload.transaction_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify either payment_id or transaction_id to dispute",
        )

    linked_payment = None
    linked_transaction = None

    if payload.payment_id:
        linked_payment = db.get(Payment, payload.payment_id)
        if not linked_payment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payment not found",
            )
        if linked_payment.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only dispute your own payments",
            )

    if payload.transaction_id:
        linked_transaction = db.get(Transaction, payload.transaction_id)
        if not linked_transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found",
            )
        if linked_transaction.sender_account.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only dispute transactions sent from your own account",
            )

    # 3. Prevent duplicate active disputes on the same item
    active_statuses = [
        DisputeStatus.OPEN,
        DisputeStatus.INVESTIGATING,
        DisputeStatus.AWAITING_CUSTOMER,
        DisputeStatus.ESCALATED,
    ]
    if payload.payment_id:
        dup_stmt = select(Dispute).where(
            Dispute.payment_id == payload.payment_id,
            Dispute.status.in_(active_statuses),
        )
        if db.scalar(dup_stmt):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An active dispute already exists for this payment",
            )
    if payload.transaction_id:
        dup_stmt = select(Dispute).where(
            Dispute.transaction_id == payload.transaction_id,
            Dispute.status.in_(active_statuses),
        )
        if db.scalar(dup_stmt):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An active dispute already exists for this transaction",
            )

    # 4. Check for auto-link to open reconciliation exception
    linked_exception_id = None
    linked_exc = None
    if payload.payment_id:
        recon_stmt = select(ReconciliationException).where(
            ReconciliationException.payment_id == payload.payment_id,
            ReconciliationException.status == ExceptionStatus.OPEN,
        )
        linked_exc = db.scalar(recon_stmt)
        if linked_exc:
            linked_exception_id = linked_exc.id

    # 5. Calculate SLA
    now_utc = datetime.now(timezone.utc)
    sla_seconds = _get_sla_seconds(payload.category)
    sla_due_at = now_utc + timedelta(seconds=sla_seconds)
    case_ref = _generate_case_ref(db)

    dispute = Dispute(
        case_ref=case_ref,
        user_id=current_user.id,
        payment_id=payload.payment_id,
        transaction_id=payload.transaction_id,
        category=payload.category,
        description=payload.description,
        status=DisputeStatus.OPEN,
        sla_due_at=sla_due_at,
        linked_exception_id=linked_exception_id,
        created_at=now_utc,
        updated_at=now_utc,
    )
    db.add(dispute)
    db.flush()

    # Initial dispute event
    init_event = DisputeEvent(
        dispute_id=dispute.id,
        actor_user_id=current_user.id,
        from_status=None,
        to_status=DisputeStatus.OPEN.value,
        note="Dispute case filed by customer.",
        visible_to_customer=True,
        created_at=now_utc,
    )
    db.add(init_event)

    if linked_exc:
        link_event = DisputeEvent(
            dispute_id=dispute.id,
            actor_user_id=None,
            from_status=None,
            to_status=DisputeStatus.OPEN.value,
            note=f"Auto-linked to open reconciliation exception #{linked_exc.id} ({linked_exc.exception_type.value})",
            visible_to_customer=True,
            created_at=now_utc,
        )
        db.add(link_event)

    record_event(
        db=db,
        event_type="DISPUTE_FILED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="dispute",
        entity_id=str(dispute.id),
        outcome="SUCCESS",
        details={
            "case_ref": dispute.case_ref,
            "category": dispute.category.value,
            "payment_id": dispute.payment_id,
            "transaction_id": dispute.transaction_id,
            "sla_due_at": sla_due_at.isoformat(),
            "linked_exception_id": linked_exception_id,
        },
        ip_address=ip_address,
    )

    response_dict = {
        "id": dispute.id,
        "case_ref": dispute.case_ref,
        "category": dispute.category.value,
        "description": dispute.description,
        "status": dispute.status.value,
        "sla_due_at": dispute.sla_due_at.isoformat(),
        "created_at": dispute.created_at.isoformat(),
        "updated_at": dispute.updated_at.isoformat(),
        "timeline": [
            {
                "id": init_event.id,
                "from_status": init_event.from_status,
                "to_status": init_event.to_status,
                "note": init_event.note,
                "created_at": init_event.created_at.isoformat(),
            }
        ],
    }

    # Store idempotency record
    idemp_rec = IdempotencyKey(
        idempotency_key=idempotency_key,
        user_id=current_user.id,
        request_hash=payload_hash,
        response_status_code=status.HTTP_201_CREATED,
        response_body=response_dict,
        created_at=now_utc,
    )
    db.add(idemp_rec)
    db.commit()
    db.refresh(dispute)
    return response_dict


def _check_separation_of_duties(
    db: Session,
    dispute: Dispute,
    staff_user: User,
    action_name: str,
    ip_address: str | None = None,
) -> None:
    """Enforce separation of duties: a staff member cannot work their own dispute."""
    if dispute.user_id == staff_user.id:
        record_event_independent(
            event_type="ACCESS_DENIED_SEPARATION_OF_DUTIES",
            actor_user_id=staff_user.id,
            actor_role=staff_user.role.value,
            entity_type="dispute",
            entity_id=str(dispute.id),
            outcome="DENIED",
            details={
                "action": action_name,
                "reason": "Staff member cannot process disputes filed by themselves",
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of duties: you cannot investigate, assign, or resolve your own dispute",
        )


def assign_dispute(
    db: Session,
    dispute_id: int,
    staff_user: User,
    target_assignee_id: int | None,
    ip_address: str | None = None,
) -> Dispute:
    """Assign dispute to self or (admin only) to another user."""
    dispute = db.get(Dispute, dispute_id)
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")

    _check_separation_of_duties(db, dispute, staff_user, "ASSIGN_DISPUTE", ip_address)

    assignee_id = target_assignee_id or staff_user.id

    if assignee_id != staff_user.id and staff_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can assign disputes to other staff members",
        )

    assignee = db.get(User, assignee_id)
    if not assignee or not assignee.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignee user not found or inactive")

    dispute.assigned_to = assignee_id
    now_utc = datetime.now(timezone.utc)
    dispute.updated_at = now_utc

    event = DisputeEvent(
        dispute_id=dispute.id,
        actor_user_id=staff_user.id,
        from_status=dispute.status.value,
        to_status=dispute.status.value,
        note=f"Assigned to {assignee.full_name} ({assignee.email})",
        visible_to_customer=False,
        created_at=now_utc,
    )
    db.add(event)

    record_event(
        db=db,
        event_type="DISPUTE_ASSIGNED",
        actor_user_id=staff_user.id,
        actor_role=staff_user.role.value,
        entity_type="dispute",
        entity_id=str(dispute.id),
        outcome="SUCCESS",
        details={"assigned_to": assignee_id, "case_ref": dispute.case_ref},
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(dispute)
    return dispute


def update_dispute_status(
    db: Session,
    dispute_id: int,
    staff_user: User,
    target_status: DisputeStatus,
    note: str,
    visible_to_customer: bool,
    ip_address: str | None = None,
) -> Dispute:
    """Move dispute status between workflow stages with state machine enforcement."""
    dispute = db.get(Dispute, dispute_id)
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")

    _check_separation_of_duties(db, dispute, staff_user, "UPDATE_STATUS", ip_address)

    try:
        transition_dispute(
            db=db,
            dispute=dispute,
            new_status=target_status,
            actor_user_id=staff_user.id,
            note=note,
            visible_to_customer=visible_to_customer,
        )
    except IllegalDisputeTransition as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    record_event(
        db=db,
        event_type="DISPUTE_STATUS_UPDATED",
        actor_user_id=staff_user.id,
        actor_role=staff_user.role.value,
        entity_type="dispute",
        entity_id=str(dispute.id),
        outcome="SUCCESS",
        details={"new_status": target_status.value, "case_ref": dispute.case_ref},
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(dispute)
    return dispute


def resolve_dispute_refund(
    db: Session,
    dispute_id: int,
    staff_user: User,
    note: str,
    ip_address: str | None = None,
) -> Dispute:
    """Resolve dispute with a full refund.

    Atomic guarantees:
      - Lock dispute row with FOR UPDATE.
      - Check already resolved / refunded (409 Conflict).
      - Check if linked payment was already REVERSED (409 Conflict).
      - Lock sender account with FOR UPDATE.
      - Insert DisputeRefund (backed by UNIQUE constraint on dispute_id).
      - Credit account balance.
      - Transition dispute to RESOLVED_REFUNDED.
      - Record DISPUTE_REFUNDED audit log.
    """
    dispute = db.scalar(
        select(Dispute).where(Dispute.id == dispute_id).with_for_update()
    )
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")

    _check_separation_of_duties(db, dispute, staff_user, "RESOLVE_REFUND", ip_address)

    if dispute.status in (DisputeStatus.RESOLVED_REFUNDED, DisputeStatus.RESOLVED_REJECTED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Dispute is already closed ({dispute.status.value})",
        )

    # Check if a DisputeRefund record already exists
    existing_refund = db.scalar(select(DisputeRefund).where(DisputeRefund.dispute_id == dispute.id))
    if existing_refund:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Dispute refund has already been issued",
        )

    # Check if the payment itself was already refunded (REVERSED)
    if dispute.payment_id:
        payment = db.get(Payment, dispute.payment_id)
        if payment and payment.status == PaymentStatus.REVERSED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Payment was already reversed/refunded; duplicate refund denied",
            )
        refund_acc_id = payment.sender_account_id if payment else None
        refund_amount = payment.amount if payment else Decimal("0.00")
    elif dispute.transaction_id:
        tx = db.get(Transaction, dispute.transaction_id)
        refund_acc_id = tx.sender_account_id if tx else None
        refund_amount = tx.amount if tx else Decimal("0.00")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No linked payment or transaction")

    # Lock account row
    account = db.scalar(select(Account).where(Account.id == refund_acc_id).with_for_update())
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target refund account not found")

    now_utc = datetime.now(timezone.utc)

    # 1. Insert DisputeRefund (DB-level unique constraint prevents concurrent duplicate refund)
    refund_record = DisputeRefund(
        dispute_id=dispute.id,
        account_id=account.id,
        amount=refund_amount,
        created_at=now_utc,
    )
    db.add(refund_record)

    # 2. Credit the balance
    account.balance += refund_amount

    # 3. Transition dispute to RESOLVED_REFUNDED
    transition_dispute(
        db=db,
        dispute=dispute,
        new_status=DisputeStatus.RESOLVED_REFUNDED,
        actor_user_id=staff_user.id,
        note=f"Dispute approved: ${refund_amount} refunded to account #{account.account_number}. {note}",
        visible_to_customer=True,
    )

    record_event(
        db=db,
        event_type="DISPUTE_REFUNDED",
        actor_user_id=staff_user.id,
        actor_role=staff_user.role.value,
        entity_type="dispute",
        entity_id=str(dispute.id),
        outcome="SUCCESS",
        details={
            "case_ref": dispute.case_ref,
            "refund_amount": str(refund_amount),
            "refunded_to_account": account.id,
            "decision_note": note,
        },
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(dispute)
    return dispute


def resolve_dispute_reject(
    db: Session,
    dispute_id: int,
    staff_user: User,
    note: str,
    ip_address: str | None = None,
) -> Dispute:
    """Resolve dispute as rejected without refund."""
    dispute = db.scalar(select(Dispute).where(Dispute.id == dispute_id).with_for_update())
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")

    _check_separation_of_duties(db, dispute, staff_user, "RESOLVE_REJECT", ip_address)

    if dispute.status in (DisputeStatus.RESOLVED_REFUNDED, DisputeStatus.RESOLVED_REJECTED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Dispute is already closed ({dispute.status.value})",
        )

    transition_dispute(
        db=db,
        dispute=dispute,
        new_status=DisputeStatus.RESOLVED_REJECTED,
        actor_user_id=staff_user.id,
        note=f"Dispute rejected: {note}",
        visible_to_customer=True,
    )

    record_event(
        db=db,
        event_type="DISPUTE_REJECTED",
        actor_user_id=staff_user.id,
        actor_role=staff_user.role.value,
        entity_type="dispute",
        entity_id=str(dispute.id),
        outcome="SUCCESS",
        details={"case_ref": dispute.case_ref, "decision_note": note},
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(dispute)
    return dispute


def sweep_escalate_overdue_disputes(db: Session, ip_address: str | None = None) -> dict:
    """Find unresolved disputes past SLA deadline (+ grace) and escalate them.

    Uses with_for_update(skip_locked=True) for concurrent sweep safety.
    Running twice will not escalate the same overdue dispute again at the same level.
    """
    grace_seconds = getattr(settings, "DISPUTE_ESCALATION_GRACE_SECONDS", 0)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=grace_seconds)

    unresolved_statuses = [
        DisputeStatus.OPEN,
        DisputeStatus.INVESTIGATING,
        DisputeStatus.AWAITING_CUSTOMER,
    ]

    stmt = (
        select(Dispute)
        .where(
            Dispute.status.in_(unresolved_statuses),
            Dispute.sla_due_at <= cutoff,
        )
        .with_for_update(skip_locked=True)
    )

    overdue_disputes = list(db.scalars(stmt).all())
    now_utc = datetime.now(timezone.utc)
    escalated_count = 0

    for d in overdue_disputes:
        d.escalation_level += 1
        d.escalated_at = now_utc

        transition_dispute(
            db=db,
            dispute=d,
            new_status=DisputeStatus.ESCALATED,
            actor_user_id=None,
            note=f"Automatic SLA breach escalation: deadline was {d.sla_due_at.isoformat()} (Level {d.escalation_level})",
            visible_to_customer=True,
        )

        record_event(
            db=db,
            event_type="DISPUTE_ESCALATED",
            actor_user_id=None,
            actor_role="system",
            entity_type="dispute",
            entity_id=str(d.id),
            outcome="SUCCESS",
            details={
                "case_ref": d.case_ref,
                "escalation_level": d.escalation_level,
                "sla_due_at": d.sla_due_at.isoformat(),
            },
            ip_address=ip_address,
        )
        escalated_count += 1

    db.commit()
    return {"overdue_found": len(overdue_disputes), "escalated": escalated_count}
