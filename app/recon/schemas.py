"""
SentinelPay – Pydantic Schemas for Reconciliation (Phase 9 - Part A).
"""

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.recon.models import ExceptionStatus, ExceptionType


class ReconciliationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    started_at: datetime
    finished_at: datetime | None
    started_by: int
    payments_checked: int
    rail_records_checked: int
    exceptions_found: int
    exceptions_new: int


class ReconciliationExceptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    exception_type: ExceptionType
    payment_id: int | None
    rail_reference: str | None
    local_status: str | None
    rail_status: str | None
    local_amount: Decimal | None
    rail_amount: Decimal | None
    status: ExceptionStatus
    details: dict | None
    resolved_by: int | None
    resolved_at: datetime | None
    resolution_note: str | None
    created_at: datetime


class PaginatedExceptions(BaseModel):
    items: list[ReconciliationExceptionResponse]
    total: int
    page: int
    page_size: int


class ResolveExceptionRequest(BaseModel):
    resolution_note: str = Field(..., min_length=1, description="Reason and notes for resolution")
    status: ExceptionStatus = Field(
        ...,
        description="Target status: must be RESOLVED or IGNORED",
    )
