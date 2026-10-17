"""
SentinelPay – Router endpoints for Audit Logs (Phase 7).
Enforces strict role-based access:
  • Admin: Full access to /audit/logs, /audit/verify, and /audit/entity/{entity_type}/{entity_id}
  • Risk Analyst: Limited access to /audit/entity for "transaction" and "fraud_alert" only
  • Customer: 403 Forbidden on all audit endpoints
"""

from datetime import datetime
from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.audit.schemas import (
    AuditLogResponse,
    HashChainVerifyResponse,
    PaginatedAuditLogs,
)
from app.audit.service import verify_hash_chain
from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.database import get_db

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get(
    "/logs",
    response_model=PaginatedAuditLogs,
    summary="List paginated audit logs with filters (Admin only)",
)
def list_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    event_type: str | None = Query(None, description="Filter by event type"),
    actor_user_id: int | None = Query(None, description="Filter by actor user ID"),
    entity_type: str | None = Query(None, description="Filter by entity type"),
    entity_id: str | None = Query(None, description="Filter by entity ID"),
    outcome: str | None = Query(None, description="Filter by outcome (SUCCESS, FAILURE, DENIED)"),
    start_date: datetime | None = Query(None, description="Filter events on or after UTC datetime"),
    end_date: datetime | None = Query(None, description="Filter events on or before UTC datetime"),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> PaginatedAuditLogs:
    """Retrieve paginated audit logs ordered newest first. Restricted to ADMIN."""
    base_stmt = select(AuditLog)

    if event_type:
        base_stmt = base_stmt.where(AuditLog.event_type == event_type)
    if actor_user_id is not None:
        base_stmt = base_stmt.where(AuditLog.actor_user_id == actor_user_id)
    if entity_type:
        base_stmt = base_stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        base_stmt = base_stmt.where(AuditLog.entity_id == entity_id)
    if outcome:
        base_stmt = base_stmt.where(AuditLog.outcome == outcome.upper())
    if start_date:
        base_stmt = base_stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        base_stmt = base_stmt.where(AuditLog.created_at <= end_date)

    # Count total
    total_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = db.scalar(total_stmt) or 0

    # Paginate and sort newest first
    stmt = (
        base_stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())

    return PaginatedAuditLogs(
        items=[AuditLogResponse.model_validate(x) for x in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/entity/{entity_type}/{entity_id}",
    response_model=list[AuditLogResponse],
    summary="Get full audit timeline for an entity (oldest first)",
)
def get_entity_timeline(
    entity_type: str,
    entity_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AuditLogResponse]:
    """
    Retrieve the chronological audit timeline for a specific entity, oldest first.
    Permissions:
      - Customer: 403 Forbidden.
      - Risk Analyst: Allowed strictly for 'transaction' and 'fraud_alert'.
      - Admin: Allowed for all entities.
    """
    if current_user.role == UserRole.CUSTOMER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Customers are not permitted to view audit logs",
        )

    if current_user.role == UserRole.RISK_ANALYST:
        if entity_type.lower() not in ["transaction", "fraud_alert"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Risk analysts are restricted to transaction and fraud_alert timelines",
            )

    stmt = (
        select(AuditLog)
        .where(
            AuditLog.entity_type == entity_type.lower(),
            AuditLog.entity_id == entity_id,
        )
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    )
    logs = db.scalars(stmt).all()
    return [AuditLogResponse.model_validate(x) for x in logs]


@router.get(
    "/verify",
    response_model=HashChainVerifyResponse,
    summary="Verify cryptographic hash chain integrity across all audit logs (Admin only)",
)
def verify_audit_chain(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> HashChainVerifyResponse:
    """
    Sequentially verify hash pointers and payload signatures across all audit entries.
    Detects any database tampering, broken chain links, or altered fields.
    Restricted to ADMIN.
    """
    result = verify_hash_chain(db)
    return HashChainVerifyResponse(**result)
