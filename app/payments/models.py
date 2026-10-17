"""
SentinelPay – Payment & PaymentEvent models (Phase 8).

Payment tracks the lifecycle of a bill payment through an external rail.
PaymentEvent records every state transition for customer timeline rendering.
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import (
    Enum as SQLEnum,
    ForeignKey,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class PaymentStatus(str, Enum):
    """Payment lifecycle status.

    State machine transitions (enforced in state_machine.py):
      PROCESSING → SETTLED | FAILED | UNKNOWN
      UNKNOWN    → SETTLED | FAILED | NEEDS_INVESTIGATION
      FAILED     → REVERSED
      SETTLED    → NEEDS_INVESTIGATION
    """

    PROCESSING = "PROCESSING"
    SETTLED = "SETTLED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    REVERSED = "REVERSED"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"


class Payment(Base):
    """Bill payment record tied to a specific biller via the external rail."""

    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    payment_ref: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    sender_account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True, nullable=False)
    biller_code: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    status: Mapped[PaymentStatus] = mapped_column(
        SQLEnum(PaymentStatus, name="payment_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=PaymentStatus.PROCESSING,
        nullable=False,
        index=True,
    )
    rail_reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    attempts_count: Mapped[int] = mapped_column(default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    sender_account: Mapped["Account"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Account",
        foreign_keys=[sender_account_id],
    )
    user: Mapped["User"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[user_id],
    )
    events: Mapped[list["PaymentEvent"]] = relationship(
        "PaymentEvent",
        back_populates="payment",
        order_by="PaymentEvent.created_at.asc()",
        cascade="all, delete-orphan",
    )


class PaymentEvent(Base):
    """One row per payment state change, used to render a customer timeline."""

    __tablename__ = "payment_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    payment_id: Mapped[int] = mapped_column(ForeignKey("payments.id"), index=True, nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    payment: Mapped["Payment"] = relationship(
        "Payment",
        back_populates="events",
    )
