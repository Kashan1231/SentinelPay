"""
SentinelPay – Pydantic schemas for audit logs.
"""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    """Schema representing an audit log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    actor_user_id: int | None
    actor_role: str | None
    entity_type: str | None
    entity_id: str | None
    outcome: str
    details: dict[str, Any] | None
    ip_address: str | None
    prev_hash: str | None
    row_hash: str
    created_at: datetime


class PaginatedAuditLogs(BaseModel):
    """Paginated list of audit logs."""

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


class HashChainVerifyResponse(BaseModel):
    """Result of hash chain verification."""

    valid: bool
    checked: int
    first_broken_id: int | None
