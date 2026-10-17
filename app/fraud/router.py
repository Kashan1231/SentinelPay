"""
SentinelPay – Router for fraud review endpoints (risk_analyst & admin only).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.models import User, UserRole
from app.core.database import get_db
from app.fraud.models import AlertStatus, RiskLevel
from app.fraud.schemas import (
    DecisionRequest,
    EscalateRequest,
    FraudAlertDetailResponse,
    FraudAlertResponse,
)
from app.fraud.service import (
    approve_fraud_alert,
    escalate_fraud_alert,
    get_fraud_alert_by_id,
    list_fraud_alerts,
    reject_fraud_alert,
)

router = APIRouter(prefix="/fraud/alerts", tags=["Fraud Review"])


def require_analyst_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Authorize only risk_analyst and admin roles to access fraud review endpoints."""
    if current_user.role not in [UserRole.RISK_ANALYST, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Requires risk_analyst or admin role",
        )
    return current_user


@router.get(
    "",
    response_model=list[FraudAlertResponse],
    summary="List fraud alerts with optional filters and pagination",
)
def list_alerts(
    status_filter: AlertStatus | None = Query(None, alias="status", description="Filter by alert status"),
    risk_level: RiskLevel | None = Query(None, description="Filter by risk level"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
) -> list[FraudAlertResponse]:
    """Retrieve paginated fraud alerts with optional status and risk level filtering."""
    alerts = list_fraud_alerts(db, status_filter, risk_level, limit, offset)
    return [FraudAlertResponse.model_validate(a) for a in alerts]


@router.get(
    "/{alert_id}",
    response_model=FraudAlertDetailResponse,
    summary="Get fraud alert details with transaction details and triggered rules",
)
def get_alert(
    alert_id: int,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
) -> FraudAlertDetailResponse:
    """Retrieve full details for an alert, including underlying transaction and rule breakdown."""
    alert = get_fraud_alert_by_id(db, alert_id)
    return FraudAlertDetailResponse.model_validate(alert)


@router.post(
    "/{alert_id}/approve",
    response_model=FraudAlertDetailResponse,
    summary="Approve a held fraud alert and execute transfer",
)
def approve_alert(
    alert_id: int,
    request: Request,
    payload: DecisionRequest | None = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
) -> FraudAlertDetailResponse:
    """
    Approve held transfer under deterministic row locks with balance re-validation.
    Executes transfer atomically if funds remain sufficient, or marks FAILED if balance dropped.
    """
    ip_address = request.client.host if request.client else None
    alert = approve_fraud_alert(db, alert_id, current_user, payload, ip_address=ip_address)
    return FraudAlertDetailResponse.model_validate(alert)


@router.post(
    "/{alert_id}/reject",
    response_model=FraudAlertDetailResponse,
    summary="Reject a held fraud alert without moving money",
)
def reject_alert(
    alert_id: int,
    request: Request,
    payload: DecisionRequest | None = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
) -> FraudAlertDetailResponse:
    """Reject held transfer; status becomes REJECTED and no money is moved."""
    ip_address = request.client.host if request.client else None
    alert = reject_fraud_alert(db, alert_id, current_user, payload, ip_address=ip_address)
    return FraudAlertDetailResponse.model_validate(alert)


@router.post(
    "/{alert_id}/escalate",
    response_model=FraudAlertDetailResponse,
    summary="Escalate a fraud alert for senior review",
)
def escalate_alert(
    alert_id: int,
    request: Request,
    payload: EscalateRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
) -> FraudAlertDetailResponse:
    """Escalate alert with mandatory explanatory note."""
    ip_address = request.client.host if request.client else None
    alert = escalate_fraud_alert(db, alert_id, current_user, payload, ip_address=ip_address)
    return FraudAlertDetailResponse.model_validate(alert)
