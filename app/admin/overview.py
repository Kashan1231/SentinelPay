"""
SentinelPay – Administrative & Operations Overview Router.

Provides aggregate system statistics, operational counts, and trend series
for executive and risk dashboards.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.auth.models import User, UserRole
from app.core.database import get_db
from app.disputes.models import Dispute, DisputeStatus
from app.fraud.models import AlertStatus, FraudAlert, RiskLevel
from app.payments.models import Payment, PaymentStatus
from app.recon.models import ExceptionStatus, ReconciliationException
from app.transactions.models import Transaction

router = APIRouter(prefix="/admin", tags=["Admin Overview"])


class DailyVolumeItem(BaseModel):
    """Daily transfer transaction volume and count."""

    date: str
    count: int
    total_amount: str


class AdminOverviewResponse(BaseModel):
    """Aggregated operational metrics for staff dashboard."""

    transactions_today: int
    transactions_yesterday: int
    held_for_review: int
    open_recon_exceptions: int
    open_disputes: int
    overdue_disputes: int
    payments_by_status: dict[str, int]
    daily_volume: list[DailyVolumeItem]
    risk_level_distribution: dict[str, int]


@router.get(
    "/overview",
    response_model=AdminOverviewResponse,
    summary="Get aggregated operational dashboard metrics (Admin, Risk Analyst)",
)
def get_admin_overview(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RISK_ANALYST)),
    db: Session = Depends(get_db),
) -> AdminOverviewResponse:
    """
    Retrieve live operational overview metrics:
      - Transaction volume for today and yesterday
      - Fraud alerts held for analyst review (OPEN or UNDER_REVIEW)
      - Unresolved reconciliation exceptions in OPEN status
      - Customer disputes in OPEN status and SLA-breached overdue cases
      - Payment counts broken down by state machine status
      - 7-day daily transaction volume time series
      - Fraud alert risk level distribution
    """
    now_utc = datetime.now(timezone.utc)
    today = now_utc.date()
    today_start = datetime(today.year, today.month, today.day, 0, 0, 0, tzinfo=timezone.utc)
    today_end = today_start + timedelta(days=1)

    yesterday = today - timedelta(days=1)
    yesterday_start = datetime(yesterday.year, yesterday.month, yesterday.day, 0, 0, 0, tzinfo=timezone.utc)
    yesterday_end = today_start

    transactions_today = db.scalar(
        select(func.count(Transaction.id)).where(
            Transaction.created_at >= today_start,
            Transaction.created_at < today_end,
        )
    ) or 0

    transactions_yesterday = db.scalar(
        select(func.count(Transaction.id)).where(
            Transaction.created_at >= yesterday_start,
            Transaction.created_at < yesterday_end,
        )
    ) or 0

    held_for_review = db.scalar(
        select(func.count(FraudAlert.id)).where(
            FraudAlert.status.in_([AlertStatus.OPEN, AlertStatus.UNDER_REVIEW])
        )
    ) or 0

    open_recon_exceptions = db.scalar(
        select(func.count(ReconciliationException.id)).where(
            ReconciliationException.status == ExceptionStatus.OPEN
        )
    ) or 0

    open_disputes = db.scalar(
        select(func.count(Dispute.id)).where(
            Dispute.status == DisputeStatus.OPEN
        )
    ) or 0

    unresolved_dispute_statuses = [
        DisputeStatus.OPEN,
        DisputeStatus.INVESTIGATING,
        DisputeStatus.AWAITING_CUSTOMER,
        DisputeStatus.ESCALATED,
    ]
    overdue_disputes = db.scalar(
        select(func.count(Dispute.id)).where(
            Dispute.status.in_(unresolved_dispute_statuses),
            Dispute.sla_due_at <= now_utc,
        )
    ) or 0

    payments_by_status = {s.value: 0 for s in PaymentStatus}
    for status_val, cnt in db.execute(
        select(Payment.status, func.count(Payment.id)).group_by(Payment.status)
    ).all():
        k = status_val.value if hasattr(status_val, "value") else str(status_val)
        payments_by_status[k] = cnt

    daily_volume: list[DailyVolumeItem] = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)
        cnt, total = db.execute(
            select(
                func.count(Transaction.id),
                func.coalesce(func.sum(Transaction.amount), Decimal("0.00")),
            ).where(
                Transaction.created_at >= day_start,
                Transaction.created_at < day_end,
            )
        ).one()
        daily_volume.append(
            DailyVolumeItem(
                date=day.strftime("%Y-%m-%d"),
                count=cnt,
                total_amount=f"{Decimal(total):.2f}",
            )
        )

    risk_level_distribution = {r.value: 0 for r in RiskLevel}
    for r_val, cnt in db.execute(
        select(FraudAlert.risk_level, func.count(FraudAlert.id)).group_by(FraudAlert.risk_level)
    ).all():
        k = r_val.value if hasattr(r_val, "value") else str(r_val)
        risk_level_distribution[k] = cnt

    return AdminOverviewResponse(
        transactions_today=transactions_today,
        transactions_yesterday=transactions_yesterday,
        held_for_review=held_for_review,
        open_recon_exceptions=open_recon_exceptions,
        open_disputes=open_disputes,
        overdue_disputes=overdue_disputes,
        payments_by_status=payments_by_status,
        daily_volume=daily_volume,
        risk_level_distribution=risk_level_distribution,
    )
