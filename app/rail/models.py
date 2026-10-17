"""
SentinelPay – Rail models & enums (Phase 8).

These tables belong to the *mock biller's* system, not SentinelPay's ledger.
The rail_ prefix makes this ownership boundary obvious.  Phase 9 reconciliation
will compare rail_records against SentinelPay's payments table.
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import Enum as SQLEnum, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class FailureMode(str, Enum):
    """Deterministic failure modes for the mock biller.

    OK:                     Processes normally, returns SETTLED.
    DECLINE:                Returns FAILED – the biller refused the payment.
    TIMEOUT_AFTER_PROCESS:  Records SETTLED on the biller side, then raises
                            RailTimeout.  From our perspective, we never hear back,
                            but the biller did receive the money.
    TIMEOUT_BEFORE_PROCESS: Raises RailTimeout without recording anything.
                            The biller never received the payment.
    """

    OK = "OK"
    DECLINE = "DECLINE"
    TIMEOUT_AFTER_PROCESS = "TIMEOUT_AFTER_PROCESS"
    TIMEOUT_BEFORE_PROCESS = "TIMEOUT_BEFORE_PROCESS"


class RailRecordStatus(str, Enum):
    """Status of a record on the biller's side."""

    SETTLED = "SETTLED"
    FAILED = "FAILED"


class RailBiller(Base):
    """A biller registered in the mock payment rail."""

    __tablename__ = "rail_billers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    failure_mode: Mapped[FailureMode] = mapped_column(
        SQLEnum(FailureMode, name="failure_mode_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=FailureMode.OK,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)


class RailRecord(Base):
    """The biller's own payment ledger entry – NOT our ledger."""

    __tablename__ = "rail_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rail_reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    biller_id: Mapped[int] = mapped_column(ForeignKey("rail_billers.id"), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    status: Mapped[RailRecordStatus] = mapped_column(
        SQLEnum(RailRecordStatus, name="rail_record_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
