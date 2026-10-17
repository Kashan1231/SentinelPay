"""
SentinelPay – Account model & enums for customer bank accounts.
"""

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import Enum as SQLEnum, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AccountType(str, Enum):
    """Supported bank account types."""

    CHECKING = "checking"
    SAVINGS = "savings"


class AccountStatus(str, Enum):
    """Account operational status lifecycle."""

    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"


# Constraint: Account balance cannot be edited directly via API endpoints.
# Balance only changes atomically through the transaction engine in Phase 4.
class Account(Base):
    """Bank account database model."""

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    account_number: Mapped[str] = mapped_column(String(10), unique=True, index=True, nullable=False)
    account_type: Mapped[AccountType] = mapped_column(
        SQLEnum(AccountType, name="account_type_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    balance: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        default=Decimal("0.00"),
        nullable=False,
    )
    status: Mapped[AccountStatus] = mapped_column(
        SQLEnum(AccountStatus, name="account_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=AccountStatus.ACTIVE,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ───────────────────────────────────────
    user: Mapped["User"] = relationship("User", back_populates="accounts")  # type: ignore[name-defined] # noqa: F821
