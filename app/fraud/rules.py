"""
SentinelPay – Explainable fraud detection rules.

Each rule is a small, independent, pure function returning (points, reason) or None.
This design provides explainability: every flagged transaction stores exactly which
rules fired and why, contrasting deliberately with opaque black-box scoring.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.core.config import settings


def rule_large_amount(
    amount: Decimal,
    threshold: Decimal | None = None,
    points: int | None = None,
) -> tuple[int, str] | None:
    """
    LARGE_AMOUNT rule:
    Fires when the transfer amount is greater than or equal to the configurable threshold.
    """
    limit = threshold if threshold is not None else settings.FRAUD_LARGE_AMOUNT_THRESHOLD
    pts = points if points is not None else settings.FRAUD_LARGE_AMOUNT_POINTS

    if amount >= limit:
        return (pts, f"Amount ({amount:.2f}) meets or exceeds large amount threshold ({limit:.2f})")
    return None


def rule_high_velocity(
    recent_transfer_count: int,
    threshold_count: int | None = None,
    points: int | None = None,
) -> tuple[int, str] | None:
    """
    HIGH_VELOCITY rule:
    Fires when the sender made more than N transfers in the last hour.
    """
    limit = threshold_count if threshold_count is not None else settings.FRAUD_HIGH_VELOCITY_COUNT
    pts = points if points is not None else settings.FRAUD_HIGH_VELOCITY_POINTS

    if recent_transfer_count > limit:
        return (pts, f"Sender made {recent_transfer_count} transfers in the last hour (exceeds limit of {limit})")
    return None


def rule_new_recipient_large(
    is_first_transfer: bool,
    amount: Decimal,
    threshold: Decimal | None = None,
    points: int | None = None,
) -> tuple[int, str] | None:
    """
    NEW_RECIPIENT_LARGE rule:
    Fires on first-ever transfer to this recipient AND amount meets or exceeds threshold.
    """
    limit = threshold if threshold is not None else settings.FRAUD_NEW_RECIPIENT_THRESHOLD
    pts = points if points is not None else settings.FRAUD_NEW_RECIPIENT_POINTS

    if is_first_transfer and amount >= limit:
        return (pts, f"First-time transfer to recipient with amount ({amount:.2f}) >= threshold ({limit:.2f})")
    return None


def rule_near_limit(
    amount: Decimal,
    single_limit: Decimal | None = None,
    percent_threshold: Decimal | None = None,
    points: int | None = None,
) -> tuple[int, str] | None:
    """
    NEAR_LIMIT rule:
    Fires when amount is within 10% of the single-transfer limit (amount >= 0.90 * single_limit).
    """
    limit = single_limit if single_limit is not None else settings.SINGLE_TRANSFER_LIMIT
    pct = percent_threshold if percent_threshold is not None else settings.FRAUD_NEAR_LIMIT_PERCENT
    pts = points if points is not None else settings.FRAUD_NEAR_LIMIT_POINTS

    threshold_amount = limit * pct
    if amount >= threshold_amount:
        return (pts, f"Amount ({amount:.2f}) is within {int((1 - pct) * 100)}% of single transfer limit ({limit:.2f})")
    return None


def rule_new_account(
    account_created_at: datetime,
    threshold_days: int | None = None,
    points: int | None = None,
    current_time: datetime | None = None,
) -> tuple[int, str] | None:
    """
    NEW_ACCOUNT rule:
    Fires when the sender's account was created fewer than N days ago.
    """
    days_limit = threshold_days if threshold_days is not None else settings.FRAUD_NEW_ACCOUNT_DAYS
    pts = points if points is not None else settings.FRAUD_NEW_ACCOUNT_POINTS

    now = current_time or datetime.now(timezone.utc)
    if account_created_at.tzinfo is None:
        account_created_at = account_created_at.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    age = now - account_created_at
    if age < timedelta(days=days_limit):
        return (pts, f"Sender account is new ({age.days} days old, threshold is {days_limit} days)")
    return None
