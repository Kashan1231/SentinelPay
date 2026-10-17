"""
SentinelPay – Rule-based fraud evaluation engine.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.fraud.models import RiskLevel
from app.fraud.rules import (
    rule_high_velocity,
    rule_large_amount,
    rule_near_limit,
    rule_new_account,
    rule_new_recipient_large,
)
from app.transactions.models import Transaction, TransactionStatus


@dataclass
class FraudEvaluationResult:
    """Result of evaluating a proposed transfer through all fraud rules."""

    risk_score: int
    risk_level: RiskLevel
    triggered_rules: list[dict[str, Any]]


def compute_risk_level(score: int) -> RiskLevel:
    """
    Score = sum of points capped at 100.
    Levels:
      0-29:  LOW
      30-59: MEDIUM
      60-100: HIGH
    """
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def evaluate_transaction(
    db: Session,
    sender_account: Account,
    recipient_account: Account,
    amount: Decimal,
) -> FraudEvaluationResult:
    """
    Evaluate all fraud rules against a proposed transfer.
    Computes explainable triggered rules, total score (capped at 100), and risk level.
    """
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    # 1. Gather context from DB
    # Velocity: count of transfers from sender account in the last hour (excluding failed transfers)
    velocity_stmt = select(func.count(Transaction.id)).where(
        Transaction.sender_account_id == sender_account.id,
        Transaction.created_at >= one_hour_ago,
        Transaction.status != TransactionStatus.FAILED,
    )
    recent_transfer_count = db.scalar(velocity_stmt) or 0

    # Prior transfer history to this recipient
    prior_tx_stmt = select(Transaction.id).where(
        Transaction.sender_account_id == sender_account.id,
        Transaction.recipient_account_id == recipient_account.id,
        Transaction.status == TransactionStatus.COMPLETED,
    )
    is_first_transfer = db.scalar(prior_tx_stmt) is None

    # 2. Evaluate individual rules
    triggered_rules: list[dict[str, Any]] = []

    # Rule 1: LARGE_AMOUNT
    res_large = rule_large_amount(amount)
    if res_large:
        triggered_rules.append({"rule": "LARGE_AMOUNT", "points": res_large[0], "reason": res_large[1]})

    # Rule 2: HIGH_VELOCITY
    res_velocity = rule_high_velocity(recent_transfer_count)
    if res_velocity:
        triggered_rules.append({"rule": "HIGH_VELOCITY", "points": res_velocity[0], "reason": res_velocity[1]})

    # Rule 3: NEW_RECIPIENT_LARGE
    res_new_recip = rule_new_recipient_large(is_first_transfer, amount)
    if res_new_recip:
        triggered_rules.append({"rule": "NEW_RECIPIENT_LARGE", "points": res_new_recip[0], "reason": res_new_recip[1]})

    # Rule 4: NEAR_LIMIT
    res_near_limit = rule_near_limit(amount)
    if res_near_limit:
        triggered_rules.append({"rule": "NEAR_LIMIT", "points": res_near_limit[0], "reason": res_near_limit[1]})

    # Rule 5: NEW_ACCOUNT
    res_new_acc = rule_new_account(sender_account.created_at, current_time=now)
    if res_new_acc:
        triggered_rules.append({"rule": "NEW_ACCOUNT", "points": res_new_acc[0], "reason": res_new_acc[1]})

    # 3. Aggregate points & determine level
    total_points = sum(r["points"] for r in triggered_rules)
    final_score = min(total_points, 100)
    risk_level = compute_risk_level(final_score)

    return FraudEvaluationResult(
        risk_score=final_score,
        risk_level=risk_level,
        triggered_rules=triggered_rules,
    )
