"""
SentinelPay – Rail admin router (Phase 8).

Provides admin-only endpoints for managing mock billers (e.g. changing failure mode
for demos and tests).
"""

from pydantic import BaseModel, ConfigDict, Field

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.auth.models import User, UserRole
from app.core.database import get_db
from app.rail.models import FailureMode, RailBiller

router = APIRouter(prefix="/rail", tags=["Rail (Mock Biller)"])


class FailureModeUpdate(BaseModel):
    failure_mode: FailureMode = Field(..., description="New failure mode for the biller")


class BillerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    name: str
    failure_mode: FailureMode
    is_active: bool


@router.patch(
    "/billers/{code}/failure-mode",
    response_model=BillerResponse,
    summary="Change a biller's failure mode (Admin only, for demos and tests)",
)
def update_biller_failure_mode(
    code: str,
    payload: FailureModeUpdate,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> RailBiller:
    """Update the deterministic failure mode of a mock biller.

    Used by admins during demos and tests to simulate different biller behaviours
    (OK, DECLINE, TIMEOUT_AFTER_PROCESS, TIMEOUT_BEFORE_PROCESS).
    """
    stmt = select(RailBiller).where(RailBiller.code == code)
    biller = db.scalar(stmt)
    if not biller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Biller with code '{code}' not found",
        )
    biller.failure_mode = payload.failure_mode
    db.commit()
    db.refresh(biller)
    return biller


@router.get(
    "/billers",
    response_model=list[BillerResponse],
    summary="List all billers (Admin only)",
)
def list_billers(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[RailBiller]:
    """List all registered mock billers and their current failure mode."""
    stmt = select(RailBiller).order_by(RailBiller.id)
    return list(db.scalars(stmt).all())
