"""
SentinelPay – Router endpoints for bill payments and admin sweep (Phase 8).
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import check_rate_limit
from app.payments.models import Payment, PaymentStatus
from app.payments.recovery import sweep_stuck_payments
from app.payments.schemas import (
    CUSTOMER_STATUS_MESSAGES,
    PaginatedPayments,
    PaymentCreate,
    PaymentDetailResponse,
    PaymentEventResponse,
    PaymentResponse,
)
from app.payments.service import initiate_payment

router = APIRouter(prefix="/payments", tags=["Payments"])


def _payment_to_response(payment: Payment) -> PaymentResponse:
    """Convert a Payment ORM object to a response with timeline and status message."""
    timeline = [
        PaymentEventResponse.model_validate(e) for e in (payment.events or [])
    ]
    return PaymentResponse(
        id=payment.id,
        payment_ref=payment.payment_ref,
        sender_account_id=payment.sender_account_id,
        biller_code=payment.biller_code,
        amount=payment.amount,
        status=payment.status,
        status_message=CUSTOMER_STATUS_MESSAGES.get(payment.status.value, ""),
        created_at=payment.created_at,
        updated_at=payment.updated_at,
        timeline=timeline,
    )


@router.post(
    "",
    response_model=PaymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate a bill payment through the external rail",
)
def create_payment(
    payload: PaymentCreate,
    request: Request,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Execute a bill payment: debit sender, call biller rail, apply outcome.

    Requires an 'Idempotency-Key' request header.
    """
    if not idempotency_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Idempotency-Key header",
        )

    # Per-user rate limiting on payments
    check_rate_limit(
        request=request,
        endpoint_key="payments",
        key_type="user",
        user_id=current_user.id,
        max_requests=settings.RATE_LIMIT_PAYMENT_MAX,
        window_seconds=settings.RATE_LIMIT_PAYMENT_WINDOW_SECONDS,
        db=db,
    )

    ip_address = request.client.host if request.client else None
    return initiate_payment(db, current_user, payload, idempotency_key, ip_address=ip_address)


@router.get(
    "",
    response_model=list[PaymentResponse],
    summary="List own payments (newest first)",
)
def list_my_payments(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[PaymentResponse]:
    """Retrieve all payments initiated by the current user, newest first."""
    stmt = (
        select(Payment)
        .where(Payment.user_id == current_user.id)
        .order_by(Payment.created_at.desc())
    )
    payments = db.scalars(stmt).all()
    return [_payment_to_response(p) for p in payments]


@router.get(
    "/{payment_id}",
    response_model=PaymentDetailResponse,
    summary="Get single payment details with timeline",
)
def get_payment_by_id(
    payment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaymentDetailResponse:
    """Retrieve payment details with full event timeline.

    Ownership check: Permitted ONLY if the current user owns the payment,
    or if the current user holds role ADMIN / RISK_ANALYST.
    Customers never see rail internals or failure_mode.
    """
    payment = db.get(Payment, payment_id)
    if not payment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment not found",
        )

    is_owner = payment.user_id == current_user.id
    is_privileged = current_user.role in [UserRole.ADMIN, UserRole.RISK_ANALYST]

    if not (is_owner or is_privileged):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You are not the owner of this payment",
        )

    return _payment_to_response(payment)


# ── Admin endpoints ─────────────────────────────────────────

admin_router = APIRouter(prefix="/admin/payments", tags=["Admin Payments"])


@admin_router.get(
    "",
    response_model=PaginatedPayments,
    summary="List all payments with filters (Admin/Risk Analyst)",
)
def list_all_payments(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: PaymentStatus | None = Query(None, alias="status"),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RISK_ANALYST)),
    db: Session = Depends(get_db),
) -> PaginatedPayments:
    """Paginated list of all payments with optional status filter."""
    base_stmt = select(Payment)
    if status_filter:
        base_stmt = base_stmt.where(Payment.status == status_filter)

    total = db.scalar(select(func.count()).select_from(base_stmt.subquery())) or 0

    stmt = (
        base_stmt.order_by(Payment.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())

    return PaginatedPayments(
        items=[_payment_to_response(p) for p in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@admin_router.post(
    "/sweep",
    summary="Sweep stuck payments (Admin only)",
)
def sweep_payments(
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    """Find payments stuck in PROCESSING or UNKNOWN beyond the configured threshold
    and attempt to resolve each one via rail status inquiry.

    Returns a summary: {found, resolved, errors}.
    """
    ip_address = request.client.host if request.client else None
    return sweep_stuck_payments(db, ip_address=ip_address)
