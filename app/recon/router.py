"""
SentinelPay – Reconciliation Router Endpoints (Phase 9 - Part A).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.auth.models import User, UserRole
from app.core.database import get_db
from app.recon.models import (
    ExceptionStatus,
    ExceptionType,
    ReconciliationException,
    ReconciliationRun,
)
from app.recon.schemas import (
    PaginatedExceptions,
    ReconciliationExceptionResponse,
    ReconciliationRunResponse,
    ResolveExceptionRequest,
)
from app.recon.service import (
    resolve_reconciliation_exception,
    run_reconciliation,
)

router = APIRouter(prefix="/admin/recon", tags=["Reconciliation (Admin)"])


@router.post(
    "/run",
    response_model=ReconciliationRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Run batch reconciliation (Admin only)",
)
def trigger_reconciliation(
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> ReconciliationRun:
    """Execute a read-only batch reconciliation run.

    Detects MISSING_AT_BILLER, ORPHAN_RAIL_RECORD, STATUS_MISMATCH,
    AMOUNT_MISMATCH, and SUSPECTED_DUPLICATE.
    NEVER changes account balances or payment statuses.
    """
    ip_address = request.client.host if request.client else None
    return run_reconciliation(db, current_user, ip_address=ip_address)


@router.get(
    "/exceptions",
    response_model=PaginatedExceptions,
    summary="List reconciliation exceptions (Admin, Risk Analyst)",
)
def list_exceptions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: ExceptionStatus | None = Query(None, alias="status"),
    type_filter: ExceptionType | None = Query(None, alias="exception_type"),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RISK_ANALYST)),
    db: Session = Depends(get_db),
) -> PaginatedExceptions:
    """Retrieve paginated reconciliation exceptions with optional filters."""
    base_stmt = select(ReconciliationException)
    if status_filter:
        base_stmt = base_stmt.where(ReconciliationException.status == status_filter)
    if type_filter:
        base_stmt = base_stmt.where(ReconciliationException.exception_type == type_filter)

    total = db.scalar(select(func.count()).select_from(base_stmt.subquery())) or 0

    stmt = (
        base_stmt.order_by(ReconciliationException.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())

    return PaginatedExceptions(
        items=[ReconciliationExceptionResponse.model_validate(x) for x in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/exceptions/{exception_id}",
    response_model=ReconciliationExceptionResponse,
    summary="Get single reconciliation exception details (Admin, Risk Analyst)",
)
def get_exception(
    exception_id: int,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RISK_ANALYST)),
    db: Session = Depends(get_db),
) -> ReconciliationException:
    """Retrieve full details of a specific reconciliation exception."""
    exc = db.get(ReconciliationException, exception_id)
    if not exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reconciliation exception {exception_id} not found",
        )
    return exc


@router.post(
    "/exceptions/{exception_id}/resolve",
    response_model=ReconciliationExceptionResponse,
    summary="Resolve or ignore a reconciliation exception (Admin only)",
)
def resolve_exception(
    exception_id: int,
    payload: ResolveExceptionRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> ReconciliationException:
    """Resolve an exception by marking it RESOLVED or IGNORED with a note.

    Returns 409 if already resolved or closed.
    CHANGES NO BALANCES OR PAYMENT STATUSES.
    """
    if payload.status not in (ExceptionStatus.RESOLVED, ExceptionStatus.IGNORED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status must be RESOLVED or IGNORED",
        )
    ip_address = request.client.host if request.client else None
    return resolve_reconciliation_exception(
        db,
        exception_id=exception_id,
        admin_user=current_user,
        payload=payload,
        ip_address=ip_address,
    )
