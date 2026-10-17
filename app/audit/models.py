"""
SentinelPay – Audit log model and enums.
Part of Phase 7: Tamper-evident, append-only audit trail.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class AuditEventType(str, Enum):
    # Auth
    USER_REGISTERED = "USER_REGISTERED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"

    # Accounts
    ACCOUNT_CREATED = "ACCOUNT_CREATED"

    # Transactions
    TRANSFER_COMPLETED = "TRANSFER_COMPLETED"
    TRANSFER_HELD = "TRANSFER_HELD"
    TRANSFER_REJECTED_LIMIT = "TRANSFER_REJECTED_LIMIT"
    TRANSFER_FAILED = "TRANSFER_FAILED"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"

    # Fraud review
    ALERT_APPROVED = "ALERT_APPROVED"
    ALERT_REJECTED = "ALERT_REJECTED"
    ALERT_ESCALATED = "ALERT_ESCALATED"
    ALERT_APPROVE_FAILED_FUNDS = "ALERT_APPROVE_FAILED_FUNDS"
    ACCESS_DENIED_SEPARATION_OF_DUTIES = "ACCESS_DENIED_SEPARATION_OF_DUTIES"

    # Payments (Phase 8)
    PAYMENT_INITIATED = "PAYMENT_INITIATED"
    PAYMENT_SETTLED = "PAYMENT_SETTLED"
    PAYMENT_FAILED = "PAYMENT_FAILED"
    PAYMENT_UNKNOWN = "PAYMENT_UNKNOWN"
    PAYMENT_REVERSED = "PAYMENT_REVERSED"
    PAYMENT_NEEDS_INVESTIGATION = "PAYMENT_NEEDS_INVESTIGATION"
    PAYMENT_REJECTED_LIMIT = "PAYMENT_REJECTED_LIMIT"
    PAYMENT_INQUIRY_PENDING = "PAYMENT_INQUIRY_PENDING"


class AuditLog(Base):
    """
    Append-only audit log table.
    Guaranteed immutable via PostgreSQL trigger blocking UPDATE and DELETE.
    Cryptographically chained via SHA-256 hash pointer (prev_hash -> row_hash).
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
    )

    actor = relationship("User", foreign_keys=[actor_user_id])
