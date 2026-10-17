"""
SentinelPay – Schemas for fraud alerts and analyst review decisions.
"""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from app.fraud.models import AlertStatus, RiskLevel
from app.transactions.schemas import TransactionResponse


class TriggeredRule(BaseModel):
    """Explainable rule trigger item."""

    rule: str
    points: int
    reason: str


class FraudAlertResponse(BaseModel):
    """Alert summary representation for analyst review dashboard."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    transaction_id: int
    risk_score: int
    risk_level: RiskLevel
    triggered_rules: list[TriggeredRule]
    status: AlertStatus
    reviewed_by: int | None = None
    reviewed_at: datetime | None = None
    decision_note: str | None = None
    created_at: datetime


class FraudAlertDetailResponse(FraudAlertResponse):
    """Detailed alert representation including full transaction details."""

    transaction: TransactionResponse


class DecisionRequest(BaseModel):
    """Payload for approving or rejecting an alert."""

    note: str | None = None


class EscalateRequest(BaseModel):
    """Payload for escalating an alert (requires a non-empty note)."""

    note: str = Field(..., min_length=1, description="Reason for escalation")
