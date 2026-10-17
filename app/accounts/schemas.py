"""
SentinelPay – Pydantic schemas for bank accounts.
"""

from datetime import datetime
from decimal import Decimal
from pydantic import BaseModel, ConfigDict

from app.accounts.models import AccountStatus, AccountType


class AccountCreate(BaseModel):
    """Payload required to create a new bank account.
    user_id is derived from the authenticated token, NEVER from the request body.
    """

    account_type: AccountType = AccountType.CHECKING


class AccountResponse(BaseModel):
    """Account representation returned by endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    account_number: str
    account_type: AccountType
    balance: Decimal
    status: AccountStatus
    created_at: datetime
