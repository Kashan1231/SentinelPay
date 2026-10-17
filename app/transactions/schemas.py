"""
SentinelPay – Pydantic schemas for transactions.
"""

from datetime import datetime
from decimal import Decimal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.validators import validate_monetary_amount
from app.transactions.models import TransactionStatus


class TransactionCreate(BaseModel):
    """Payload required to initiate a money transfer.
    Sender account is derived from the authenticated user's account.
    """

    recipient_account_number: str = Field(..., min_length=10, max_length=10)
    amount: Decimal = Field(..., gt=Decimal("0.00"), description="Transfer amount must be greater than zero")
    description: str | None = None
    sender_account_id: int | None = None

    @field_validator("amount")
    @classmethod
    def check_amount(cls, v: Decimal) -> Decimal:
        return validate_monetary_amount(v)


class TransactionResponse(BaseModel):
    """Transaction ledger response representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    transaction_ref: str
    sender_account_id: int
    recipient_account_id: int
    amount: Decimal
    status: TransactionStatus
    description: str | None
    message: str | None = None
    created_at: datetime
    completed_at: datetime | None


class StaffTransactionResponse(BaseModel):
    """Staff-facing transaction representation including risk indicators."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    transaction_ref: str
    sender_account_id: int
    recipient_account_id: int
    amount: Decimal
    status: TransactionStatus
    description: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class PaginatedStaffTransactions(BaseModel):
    """Paginated list of transactions for staff."""

    items: list[StaffTransactionResponse]
    total: int
    page: int
    page_size: int
    pages: int
