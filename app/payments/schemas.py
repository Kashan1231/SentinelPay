"""
SentinelPay – Pydantic schemas for payments (Phase 8).
"""

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.validators import validate_monetary_amount
from app.payments.models import PaymentStatus


class PaymentCreate(BaseModel):
    """Payload required to initiate a bill payment."""

    biller_code: str = Field(..., min_length=1, max_length=64)
    amount: Decimal = Field(..., gt=Decimal("0.00"), description="Payment amount must be greater than zero")
    sender_account_id: int | None = None

    @field_validator("amount")
    @classmethod
    def check_amount(cls, v: Decimal) -> Decimal:
        return validate_monetary_amount(v)


class PaymentEventResponse(BaseModel):
    """A single event in the payment timeline."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    from_status: str | None
    to_status: str
    note: str | None
    created_at: datetime


# Customer-friendly messages for each status (no rail internals exposed).
CUSTOMER_STATUS_MESSAGES: dict[str, str] = {
    "PROCESSING": "Your payment is being processed.",
    "SETTLED": "Your payment has been confirmed by the biller.",
    "FAILED": "Your payment could not be completed.",
    "UNKNOWN": "We are confirming your payment with the biller.",
    "REVERSED": "Your payment was reversed and the amount has been refunded.",
    "NEEDS_INVESTIGATION": "Your payment requires manual review. Our team is investigating.",
}


class PaymentResponse(BaseModel):
    """Payment response visible to customers."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    payment_ref: str
    sender_account_id: int
    biller_code: str
    amount: Decimal
    status: PaymentStatus
    status_message: str | None = None
    created_at: datetime
    updated_at: datetime
    timeline: list[PaymentEventResponse] = []


class PaymentDetailResponse(PaymentResponse):
    """Payment response with full timeline for detail view."""

    pass


class PaginatedPayments(BaseModel):
    """Paginated list of payments for admin view."""

    items: list[PaymentResponse]
    total: int
    page: int
    page_size: int
