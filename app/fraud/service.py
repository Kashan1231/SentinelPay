"""
SentinelPay – Service layer for fraud alert management and analyst decisions.
"""

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.accounts.models import Account, AccountStatus
from app.audit.service import record_event, record_event_independent
from app.auth.models import User
from app.fraud.models import AlertStatus, FraudAlert, RiskLevel
from app.fraud.schemas import DecisionRequest, EscalateRequest
from app.transactions.models import Transaction, TransactionStatus


def list_fraud_alerts(
    db: Session,
    status_filter: AlertStatus | None = None,
    risk_level_filter: RiskLevel | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[FraudAlert]:
    """Retrieve paginated fraud alerts with optional status and risk_level filtering."""
    stmt = select(FraudAlert).order_by(FraudAlert.created_at.desc())

    if status_filter is not None:
        stmt = stmt.where(FraudAlert.status == status_filter)
    if risk_level_filter is not None:
        stmt = stmt.where(FraudAlert.risk_level == risk_level_filter)

    stmt = stmt.offset(offset).limit(limit)
    return list(db.scalars(stmt).all())


def get_fraud_alert_by_id(db: Session, alert_id: int) -> FraudAlert:
    """Retrieve single fraud alert with full transaction details."""
    stmt = (
        select(FraudAlert)
        .options(joinedload(FraudAlert.transaction))
        .where(FraudAlert.id == alert_id)
    )
    alert = db.scalar(stmt)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fraud alert not found",
        )
    return alert


def _verify_separation_of_duties(
    alert: FraudAlert,
    current_user: User,
    ip_address: str | None = None,
    db: Session | None = None,
) -> None:
    """
    SEPARATION OF DUTIES ENFORCEMENT:
    An analyst or admin who owns either the sender or recipient account
    is strictly forbidden from reviewing that transaction.
    """
    sender_account = alert.transaction.sender_account
    recipient_account = alert.transaction.recipient_account

    if (
        (sender_account and sender_account.user_id == current_user.id)
        or (recipient_account and recipient_account.user_id == current_user.id)
    ):
        record_event_independent(
            event_type="ACCESS_DENIED_SEPARATION_OF_DUTIES",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="fraud_alert",
            entity_id=str(alert.id),
            outcome="DENIED",
            details={
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id,
                "reason": "Separation of duties: Reviewer cannot be a party to the transaction",
            },
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of duties: Reviewer cannot be a party to the transaction",
        )


def approve_fraud_alert(
    db: Session,
    alert_id: int,
    current_user: User,
    payload: DecisionRequest | None = None,
    ip_address: str | None = None,
) -> FraudAlert:
    """
    Approve a held fraud alert:
    1. Lock alert row (SELECT ... FOR UPDATE) for concurrency safety.
    2. Check alert is in OPEN or UNDER_REVIEW status (return 409 if already decided).
    3. Check separation of duties (return 403 if reviewer owns either account).
    4. Re-lock both accounts in deterministic order (min_id then max_id).
    5. RE-CHECK that sender is still active and has sufficient balance.
    6. If sufficient, atomically transfer funds and mark transaction COMPLETED.
       If insufficient, mark transaction FAILED and record reason in alert note.
    7. Set alert status to RESOLVED.
    """
    # 1. Lock alert row
    stmt = (
        select(FraudAlert)
        .where(FraudAlert.id == alert_id)
        .with_for_update()
    )
    alert = db.scalar(stmt)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fraud alert not found",
        )

    # 2. Separation of duties
    _verify_separation_of_duties(alert, current_user, ip_address=ip_address, db=db)

    # 3. Check decision eligibility
    if alert.status not in [AlertStatus.OPEN, AlertStatus.UNDER_REVIEW]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert has already been decided (status: {alert.status.value})",
        )

    tx = alert.transaction

    # 4. Lock both accounts in deterministic order
    first_id = min(tx.sender_account_id, tx.recipient_account_id)
    second_id = max(tx.sender_account_id, tx.recipient_account_id)

    db.scalars(select(Account).where(Account.id == first_id).with_for_update()).first()
    db.scalars(select(Account).where(Account.id == second_id).with_for_update()).first()

    sender = db.get(Account, tx.sender_account_id)
    recipient = db.get(Account, tx.recipient_account_id)

    now_utc = datetime.now(timezone.utc)
    alert.reviewed_by = current_user.id
    alert.reviewed_at = now_utc
    alert.status = AlertStatus.RESOLVED

    # 5. Re-check sender balance and active status
    if not sender or sender.status != AccountStatus.ACTIVE or sender.balance < tx.amount:
        reason = "Insufficient funds" if (sender and sender.balance < tx.amount) else "Sender account is inactive or missing"
        tx.status = TransactionStatus.FAILED
        tx.completed_at = now_utc
        note_str = f"Approval failed: {reason}."
        if payload and payload.note:
            note_str += f" Note: {payload.note}"
        alert.decision_note = note_str

        record_event(
            db=db,
            event_type="ALERT_APPROVE_FAILED_FUNDS",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="fraud_alert",
            entity_id=str(alert.id),
            outcome="FAILURE",
            details={
                "transaction_id": tx.id,
                "reason": reason,
                "note": note_str,
            },
            ip_address=ip_address,
        )
    else:
        # Atomic execution
        sender.balance -= tx.amount
        recipient.balance += tx.amount
        tx.status = TransactionStatus.COMPLETED
        tx.completed_at = now_utc
        alert.decision_note = payload.note if (payload and payload.note) else "Transaction approved"

        record_event(
            db=db,
            event_type="ALERT_APPROVED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            entity_type="fraud_alert",
            entity_id=str(alert.id),
            outcome="SUCCESS",
            details={
                "transaction_id": tx.id,
                "amount": str(tx.amount),
                "decision_note": alert.decision_note,
            },
            ip_address=ip_address,
        )

    db.commit()
    db.refresh(alert)
    return alert


def reject_fraud_alert(
    db: Session,
    alert_id: int,
    current_user: User,
    payload: DecisionRequest | None = None,
    ip_address: str | None = None,
) -> FraudAlert:
    """
    Reject a held fraud alert:
    1. Lock alert row for concurrency safety.
    2. Check separation of duties.
    3. Check status is OPEN or UNDER_REVIEW (409 if already decided).
    4. Set transaction status to REJECTED. No money moves.
    5. Set alert status to RESOLVED.
    """
    stmt = (
        select(FraudAlert)
        .where(FraudAlert.id == alert_id)
        .with_for_update()
    )
    alert = db.scalar(stmt)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fraud alert not found",
        )

    _verify_separation_of_duties(alert, current_user, ip_address=ip_address, db=db)

    if alert.status not in [AlertStatus.OPEN, AlertStatus.UNDER_REVIEW]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert has already been decided (status: {alert.status.value})",
        )

    tx = alert.transaction
    now_utc = datetime.now(timezone.utc)

    # Transaction is rejected; no money moves
    tx.status = TransactionStatus.REJECTED
    tx.completed_at = now_utc

    alert.status = AlertStatus.RESOLVED
    alert.reviewed_by = current_user.id
    alert.reviewed_at = now_utc
    alert.decision_note = payload.note if (payload and payload.note) else "Transaction rejected"

    record_event(
        db=db,
        event_type="ALERT_REJECTED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="fraud_alert",
        entity_id=str(alert.id),
        outcome="SUCCESS",
        details={
            "transaction_id": tx.id,
            "decision_note": alert.decision_note,
        },
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(alert)
    return alert


def escalate_fraud_alert(
    db: Session,
    alert_id: int,
    current_user: User,
    payload: EscalateRequest,
    ip_address: str | None = None,
) -> FraudAlert:
    """
    Escalate a fraud alert:
    1. Lock alert row for concurrency safety.
    2. Check separation of duties.
    3. Check status is OPEN or UNDER_REVIEW (409 if already decided).
    4. Requires a non-empty note.
    5. Set alert status to ESCALATED. Transaction remains in PENDING_REVIEW.
    """
    if not payload.note or not payload.note.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Escalation requires an explanatory note",
        )

    stmt = (
        select(FraudAlert)
        .where(FraudAlert.id == alert_id)
        .with_for_update()
    )
    alert = db.scalar(stmt)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fraud alert not found",
        )

    _verify_separation_of_duties(alert, current_user, ip_address=ip_address, db=db)

    if alert.status not in [AlertStatus.OPEN, AlertStatus.UNDER_REVIEW]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert cannot be escalated; current status is '{alert.status.value}'",
        )

    now_utc = datetime.now(timezone.utc)
    alert.status = AlertStatus.ESCALATED
    alert.reviewed_by = current_user.id
    alert.reviewed_at = now_utc
    alert.decision_note = payload.note.strip()

    tx_id = alert.transaction.id if alert.transaction else None
    record_event(
        db=db,
        event_type="ALERT_ESCALATED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="fraud_alert",
        entity_id=str(alert.id),
        outcome="SUCCESS",
        details={
            "transaction_id": tx_id,
            "note": alert.decision_note,
        },
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(alert)
    return alert
