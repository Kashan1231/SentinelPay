"""
SentinelPay – Dispute & SLA Models (Phase 9 - Part B).

A dispute is a tracked case with an owner, deadline (SLA), timeline of events,
and automatic escalation when overdue. Dispute refunds are backstopped by a UNIQUE
constraint on dispute_id to guarantee that money can only ever be refunded once.
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DisputeCategory(str, Enum):
    """Reason categories for filing a dispute."""

    DUPLICATE_DEBIT = "DUPLICATE_DEBIT"
    PAID_BUT_NOT_CREDITED = "PAID_BUT_NOT_CREDITED"
    UNAUTHORIZED = "UNAUTHORIZED"
    OTHER = "OTHER"


class DisputeStatus(str, Enum):
    """Lifecycle status of a dispute case."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_CUSTOMER = "AWAITING_CUSTOMER"
    ESCALATED = "ESCALATED"
    RESOLVED_REFUNDED = "RESOLVED_REFUNDED"
    RESOLVED_REJECTED = "RESOLVED_REJECTED"


class Dispute(Base):
    """A formal customer dispute case tracked with SLA deadlines."""

    __tablename__ = "disputes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_ref: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    payment_id: Mapped[int | None] = mapped_column(ForeignKey("payments.id"), index=True, nullable=True)
    transaction_id: Mapped[int | None] = mapped_column(ForeignKey("transactions.id"), index=True, nullable=True)
    category: Mapped[DisputeCategory] = mapped_column(
        SQLEnum(
            DisputeCategory,
            name="dispute_category_enum",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[DisputeStatus] = mapped_column(
        SQLEnum(
            DisputeStatus,
            name="dispute_status_enum",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=DisputeStatus.OPEN,
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    sla_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    linked_exception_id: Mapped[int | None] = mapped_column(
        ForeignKey("reconciliation_exceptions.id"),
        index=True,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    user: Mapped["User"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[user_id],
    )
    assignee: Mapped["User"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[assigned_to],
    )
    payment: Mapped["Payment"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Payment",
        foreign_keys=[payment_id],
    )
    transaction: Mapped["Transaction"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Transaction",
        foreign_keys=[transaction_id],
    )
    linked_exception: Mapped["ReconciliationException"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "ReconciliationException",
        foreign_keys=[linked_exception_id],
    )
    events: Mapped[list["DisputeEvent"]] = relationship(
        "DisputeEvent",
        back_populates="dispute",
        order_by="DisputeEvent.created_at.asc()",
        cascade="all, delete-orphan",
    )
    refund: Mapped["DisputeRefund"] = relationship(
        "DisputeRefund",
        back_populates="dispute",
        uselist=False,
        cascade="all, delete-orphan",
    )


class DisputeEvent(Base):
    """Chronological event in the dispute lifecycle."""

    __tablename__ = "dispute_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dispute_id: Mapped[int] = mapped_column(ForeignKey("disputes.id"), index=True, nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    visible_to_customer: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    dispute: Mapped["Dispute"] = relationship("Dispute", back_populates="events")
    actor: Mapped["User"] = relationship("User", foreign_keys=[actor_user_id])  # type: ignore[name-defined] # noqa: F821


class DisputeRefund(Base):
    """Record of a financial refund issued through dispute resolution.

    CRITICAL BACKSTOP: dispute_id has a UNIQUE constraint.
    Even under high concurrency or repeated button clicks, the database engine
    strictly prevents more than one refund record per dispute case.
    """

    __tablename__ = "dispute_refunds"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dispute_id: Mapped[int] = mapped_column(
        ForeignKey("disputes.id"),
        unique=True,
        index=True,
        nullable=False,
    )
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    dispute: Mapped["Dispute"] = relationship("Dispute", back_populates="refund")
    account: Mapped["Account"] = relationship("Account", foreign_keys=[account_id])  # type: ignore[name-defined] # noqa: F821
