"""
SentinelPay – Reconciliation Models (Phase 9 - Part A).

Reconciliation detects and tracks discrepancies between SentinelPay's internal ledger
(payments table) and external biller ledgers (rail_records table).
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import (
    Column,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Table,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ExceptionType(str, Enum):
    """Types of discrepancies discovered during reconciliation."""

    MISSING_AT_BILLER = "MISSING_AT_BILLER"
    ORPHAN_RAIL_RECORD = "ORPHAN_RAIL_RECORD"
    STATUS_MISMATCH = "STATUS_MISMATCH"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    SUSPECTED_DUPLICATE = "SUSPECTED_DUPLICATE"


class ExceptionStatus(str, Enum):
    """Lifecycle status of a reconciliation exception."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


class ReconciliationRun(Base):
    """Audit record for a batch reconciliation run."""

    __tablename__ = "reconciliation_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    started_by: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    payments_checked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rail_records_checked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exceptions_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exceptions_new: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # ── Relationships ───────────────────────────────────────
    starter: Mapped["User"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[started_by],
    )
    exceptions: Mapped[list["ReconciliationException"]] = relationship(
        "ReconciliationException",
        back_populates="run",
        cascade="all, delete-orphan",
    )


class ReconciliationException(Base):
    """A discrepancy between the internal ledger and external rail ledger."""

    __tablename__ = "reconciliation_exceptions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("reconciliation_runs.id"),
        nullable=False,
        index=True,
    )
    exception_type: Mapped[ExceptionType] = mapped_column(
        SQLEnum(
            ExceptionType,
            name="recon_exception_type_enum",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )
    payment_id: Mapped[int | None] = mapped_column(
        ForeignKey("payments.id"),
        nullable=True,
        index=True,
    )
    rail_reference: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    local_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rail_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    local_amount: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    rail_amount: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    status: Mapped[ExceptionStatus] = mapped_column(
        SQLEnum(
            ExceptionStatus,
            name="recon_exception_status_enum",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ExceptionStatus.OPEN,
        nullable=False,
        index=True,
    )
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    resolved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # ── Relationships ───────────────────────────────────────
    run: Mapped["ReconciliationRun"] = relationship(
        "ReconciliationRun",
        back_populates="exceptions",
    )
    payment: Mapped["Payment"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Payment",
        foreign_keys=[payment_id],
    )
    resolver: Mapped["User"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[resolved_by],
    )

    # ── Table Constraints & Indexes ──────────────────────────
    # Partial unique index: Cannot have duplicate OPEN exceptions for the same
    # (exception_type, payment_id, rail_reference) tuple.
    __table_args__ = (
        Index(
            "uq_open_recon_exception",
            "exception_type",
            func.coalesce(payment_id, -1),
            func.coalesce(rail_reference, ""),
            unique=True,
            postgresql_where=text("status = 'OPEN'"),
        ),
    )
