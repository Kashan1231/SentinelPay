"""
SentinelPay – Transaction model & enums for money transfers.
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import JSON, Enum as SQLEnum, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.fraud.models import FraudAlert, RiskLevel


class TransactionStatus(str, Enum):
    """Transaction lifecycle status."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"


class Transaction(Base):
    """Financial transaction ledger record."""

    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    transaction_ref: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    sender_account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True, nullable=False)
    recipient_account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    status: Mapped[TransactionStatus] = mapped_column(
        SQLEnum(TransactionStatus, name="transaction_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=TransactionStatus.PENDING,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(nullable=True)
    risk_level: Mapped[RiskLevel | None] = mapped_column(
        SQLEnum(RiskLevel, name="risk_level_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # ── Relationships ───────────────────────────────────────
    sender_account: Mapped["Account"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Account",
        foreign_keys=[sender_account_id],
    )
    recipient_account: Mapped["Account"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Account",
        foreign_keys=[recipient_account_id],
    )
    fraud_alert: Mapped["FraudAlert | None"] = relationship(
        "FraudAlert",
        back_populates="transaction",
        uselist=False,
    )


class IdempotencyKey(Base):
    """
    Idempotency key record for preventing duplicate transaction requests.
    Guarantees that retry attempts with the same Idempotency-Key return the
    cached response without re-executing the transfer.
    """

    __tablename__ = "idempotency_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_status_code: Mapped[int] = mapped_column(nullable=False)
    response_body: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

