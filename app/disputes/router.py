"""
SentinelPay – Dispute Router Endpoints (Phase 9 - Part B).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import check_rate_limit
from app.disputes.models import Dispute, DisputeCategory, DisputeStatus
from app.disputes.schemas import (
    AssignDisputeRequest,
    DisputeCreate,
    DisputeCustomerResponse,
    DisputeEventResponse,
    DisputeStaffResponse,
    PaginatedStaffDisputes,
    ResolveDisputeRequest,
    UpdateDisputeStatusRequest,
)
from app.disputes.service import (
    assign_dispute,
    create_dispute,
    resolve_dispute_refund,
    resolve_dispute_reject,
    sweep_escalate_overdue_disputes,
    update_dispute_status,
)

router = APIRouter(prefix="/disputes", tags=["Disputes (Customer)"])
staff_router = APIRouter(prefix="/staff/disputes", tags=["Disputes (Staff)"])
admin_disputes_router = APIRouter(prefix="/admin/disputes", tags=["Disputes (Admin)"])


# ─────────────────────────────────────────────────────────────
# CUSTOMER ENDPOINTS
# ─────────────────────────────────────────────────────────────

def _dispute_to_customer_response(dispute: Dispute) -> DisputeCustomerResponse:
    """Format dispute for customer view, stripping non-customer-visible events."""
    visible_events = [
        DisputeEventResponse.model_validate(e)
        for e in (dispute.events or [])
        if e.visible_to_customer
    ]
    return DisputeCustomerResponse(
        id=dispute.id,
        case_ref=dispute.case_ref,
        category=dispute.category,
        description=dispute.description,
        status=dispute.status,
        sla_due_at=dispute.sla_due_at,
        created_at=dispute.created_at,
        updated_at=dispute.updated_at,
        timeline=visible_events,
    )


@router.post(
    "",
    response_model=DisputeCustomerResponse,
    status_code=status.HTTP_201_CREATED,
    summary="File a new dispute case against a payment or transaction",
)
def file_dispute(
    payload: DisputeCreate,
    request: Request,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Customer submits a dispute case. Requires Idempotency-Key."""
    if not idempotency_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Idempotency-Key header",
        )

    # Per-user rate limiting on dispute filing
    check_rate_limit(
        request=request,
        endpoint_key="disputes",
        key_type="user",
        user_id=current_user.id,
        max_requests=settings.RATE_LIMIT_DISPUTE_MAX,
        window_seconds=settings.RATE_LIMIT_DISPUTE_WINDOW_SECONDS,
        db=db,
    )

    ip_address = request.client.host if request.client else None
    return create_dispute(
        db,
        current_user=current_user,
        payload=payload,
        idempotency_key=idempotency_key,
        ip_address=ip_address,
    )


@router.get(
    "",
    response_model=list[DisputeCustomerResponse],
    summary="List own disputes (Customer)",
)
def list_my_disputes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DisputeCustomerResponse]:
    """Retrieve all dispute cases filed by the authenticated customer."""
    stmt = (
        select(Dispute)
        .where(Dispute.user_id == current_user.id)
        .order_by(Dispute.created_at.desc())
    )
    items = list(db.scalars(stmt).all())
    return [_dispute_to_customer_response(d) for d in items]


@router.get(
    "/{dispute_id}",
    response_model=DisputeCustomerResponse,
    summary="Get single dispute details and timeline (Customer)",
)
def get_my_dispute(
    dispute_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DisputeCustomerResponse:
    """Retrieve a dispute case. Restricted strictly to the case owner."""
    dispute = db.get(Dispute, dispute_id)
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")
    if dispute.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this dispute",
        )
    return _dispute_to_customer_response(dispute)


# ─────────────────────────────────────────────────────────────
# STAFF ENDPOINTS
# ─────────────────────────────────────────────────────────────

def _dispute_to_staff_response(dispute: Dispute) -> DisputeStaffResponse:
    """Format dispute for staff with all timeline events."""
    all_events = [
        DisputeEventResponse.model_validate(e)
        for e in (dispute.events or [])
    ]
    return DisputeStaffResponse(
        id=dispute.id,
        case_ref=dispute.case_ref,
        user_id=dispute.user_id,
        payment_id=dispute.payment_id,
        transaction_id=dispute.transaction_id,
        category=dispute.category,
        description=dispute.description,
        status=dispute.status,
        assigned_to=dispute.assigned_to,
        sla_due_at=dispute.sla_due_at,
        escalation_level=dispute.escalation_level,
        escalated_at=dispute.escalated_at,
        resolved_at=dispute.resolved_at,
        resolution_note=dispute.resolution_note,
        linked_exception_id=dispute.linked_exception_id,
        created_at=dispute.created_at,
        updated_at=dispute.updated_at,
        timeline=all_events,
    )


@staff_router.get(
    "",
    response_model=PaginatedStaffDisputes,
    summary="List disputes with filters (Staff)",
)
def list_staff_disputes(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: DisputeStatus | None = Query(None, alias="status"),
    category_filter: DisputeCategory | None = Query(None, alias="category"),
    assigned_to: int | None = Query(None),
    overdue: bool | None = Query(None),
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> PaginatedStaffDisputes:
    """Paginated list of all customer disputes for operations analysts."""
    base_stmt = select(Dispute)
    if status_filter:
        base_stmt = base_stmt.where(Dispute.status == status_filter)
    if category_filter:
        base_stmt = base_stmt.where(Dispute.category == category_filter)
    if assigned_to is not None:
        base_stmt = base_stmt.where(Dispute.assigned_to == assigned_to)
    if overdue is True:
        now_utc = datetime.now(timezone.utc)
        base_stmt = base_stmt.where(
            Dispute.sla_due_at <= now_utc,
            Dispute.status.in_([DisputeStatus.OPEN, DisputeStatus.INVESTIGATING, DisputeStatus.AWAITING_CUSTOMER]),
        )

    total = db.scalar(select(func.count()).select_from(base_stmt.subquery())) or 0
    stmt = (
        base_stmt.order_by(Dispute.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())

    return PaginatedStaffDisputes(
        items=[_dispute_to_staff_response(d) for d in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@staff_router.get(
    "/{dispute_id}",
    response_model=DisputeStaffResponse,
    summary="Get full dispute details (Staff)",
)
def get_staff_dispute(
    dispute_id: int,
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DisputeStaffResponse:
    dispute = db.get(Dispute, dispute_id)
    if not dispute:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dispute not found")
    return _dispute_to_staff_response(dispute)


@staff_router.post(
    "/{dispute_id}/assign",
    response_model=DisputeStaffResponse,
    summary="Assign dispute to investigator (Staff)",
)
def assign_dispute_endpoint(
    dispute_id: int,
    payload: AssignDisputeRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DisputeStaffResponse:
    ip_address = request.client.host if request.client else None
    d = assign_dispute(
        db,
        dispute_id=dispute_id,
        staff_user=current_user,
        target_assignee_id=payload.assigned_to,
        ip_address=ip_address,
    )
    return _dispute_to_staff_response(d)


@staff_router.post(
    "/{dispute_id}/status",
    response_model=DisputeStaffResponse,
    summary="Update dispute status workflow (Staff)",
)
def update_status_endpoint(
    dispute_id: int,
    payload: UpdateDisputeStatusRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DisputeStaffResponse:
    ip_address = request.client.host if request.client else None
    d = update_dispute_status(
        db,
        dispute_id=dispute_id,
        staff_user=current_user,
        target_status=payload.status,
        note=payload.note,
        visible_to_customer=payload.visible_to_customer,
        ip_address=ip_address,
    )
    return _dispute_to_staff_response(d)


@staff_router.post(
    "/{dispute_id}/resolve-refund",
    response_model=DisputeStaffResponse,
    summary="Resolve dispute with a customer refund (Staff)",
)
def resolve_refund_endpoint(
    dispute_id: int,
    payload: ResolveDisputeRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DisputeStaffResponse:
    ip_address = request.client.host if request.client else None
    d = resolve_dispute_refund(
        db,
        dispute_id=dispute_id,
        staff_user=current_user,
        note=payload.note,
        ip_address=ip_address,
    )
    return _dispute_to_staff_response(d)


@staff_router.post(
    "/{dispute_id}/resolve-reject",
    response_model=DisputeStaffResponse,
    summary="Resolve dispute as rejected without refund (Staff)",
)
def resolve_reject_endpoint(
    dispute_id: int,
    payload: ResolveDisputeRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.RISK_ANALYST, UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DisputeStaffResponse:
    ip_address = request.client.host if request.client else None
    d = resolve_dispute_reject(
        db,
        dispute_id=dispute_id,
        staff_user=current_user,
        note=payload.note,
        ip_address=ip_address,
    )
    return _dispute_to_staff_response(d)


# ─────────────────────────────────────────────────────────────
# ADMIN ESCALATION SWEEP
# ─────────────────────────────────────────────────────────────

@admin_disputes_router.post(
    "/escalation-sweep",
    summary="Sweep and escalate overdue disputes (Admin only)",
)
def run_escalation_sweep(
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    ip_address = request.client.host if request.client else None
    return sweep_escalate_overdue_disputes(db, ip_address=ip_address)
