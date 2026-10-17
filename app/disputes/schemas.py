"""
SentinelPay – Pydantic Schemas for Disputes (Phase 9 - Part B).
"""

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.disputes.models import DisputeCategory, DisputeStatus


class DisputeCreate(BaseModel):
    category: DisputeCategory
    description: str = Field(..., min_length=5, max_length=2000)
    payment_id: int | None = None
    transaction_id: int | None = None


class DisputeEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    from_status: str | None
    to_status: str
    note: str | None
    created_at: datetime


class DisputeCustomerResponse(BaseModel):
    """Customer-safe view of a dispute case."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    case_ref: str
    category: DisputeCategory
    description: str
    status: DisputeStatus
    sla_due_at: datetime
    created_at: datetime
    updated_at: datetime
    timeline: list[DisputeEventResponse] = []


class DisputeStaffResponse(BaseModel):
    """Staff view of a dispute case with internal notes, assignee, escalation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    case_ref: str
    user_id: int
    payment_id: int | None
    transaction_id: int | None
    category: DisputeCategory
    description: str
    status: DisputeStatus
    assigned_to: int | None
    sla_due_at: datetime
    escalation_level: int
    escalated_at: datetime | None
    resolved_at: datetime | None
    resolution_note: str | None
    linked_exception_id: int | None
    created_at: datetime
    updated_at: datetime
    timeline: list[DisputeEventResponse] = []


class PaginatedStaffDisputes(BaseModel):
    items: list[DisputeStaffResponse]
    total: int
    page: int
    page_size: int


class AssignDisputeRequest(BaseModel):
    assigned_to: int | None = Field(
        None,
        description="User ID to assign to. None or omitted assigns to self.",
    )


class UpdateDisputeStatusRequest(BaseModel):
    status: DisputeStatus
    note: str = Field(..., min_length=1)
    visible_to_customer: bool = True


class ResolveDisputeRequest(BaseModel):
    note: str = Field(..., min_length=1)
