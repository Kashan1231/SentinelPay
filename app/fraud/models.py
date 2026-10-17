"""
SentinelPay – FraudAlert model & enums for rule-based fraud detection.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import JSON, Enum as SQLEnum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class RiskLevel(str, Enum):
    """Fraud risk score evaluation levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AlertStatus(str, Enum):
    """Lifecycle status of a fraud review alert."""

    OPEN = "open"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class FraudAlert(Base):
    """
    Fraud alert raised by the rule engine.
    Stores explainable rule trigger breakdown and analyst review lifecycle.
    """

    __tablename__ = "fraud_alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    transaction_id: Mapped[int] = mapped_column(
        ForeignKey("transactions.id"),
        unique=True,
        index=True,
        nullable=False,
    )
    risk_score: Mapped[int] = mapped_column(nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(
        SQLEnum(RiskLevel, name="risk_level_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    triggered_rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus, name="alert_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=AlertStatus.OPEN,
        nullable=False,
        index=True,
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    transaction: Mapped["Transaction"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "Transaction",
        back_populates="fraud_alert",
    )
    reviewer: Mapped["User | None"] = relationship(  # type: ignore[name-defined] # noqa: F821
        "User",
        foreign_keys=[reviewed_by],
    )
