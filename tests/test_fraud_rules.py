"""
Unit tests for explainable fraud detection rules (Phase 6 Part C & G).

Tests each rule function in complete isolation with exact boundary conditions:
- Just below threshold (must not fire)
- Just at threshold (must fire)
- Above threshold (must fire)
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.fraud.engine import compute_risk_level
from app.fraud.models import RiskLevel
from app.fraud.rules import (
    rule_high_velocity,
    rule_large_amount,
    rule_near_limit,
    rule_new_account,
    rule_new_recipient_large,
)


def test_rule_large_amount_boundary() -> None:
    """Boundary test: LARGE_AMOUNT triggers at amount >= threshold."""
    threshold = Decimal("2000.00")
    points = 40

    # Just below threshold -> None
    assert rule_large_amount(Decimal("1999.99"), threshold=threshold, points=points) is None

    # Exactly at threshold -> Fires
    res_at = rule_large_amount(Decimal("2000.00"), threshold=threshold, points=points)
    assert res_at is not None
    assert res_at[0] == 40
    assert "meets or exceeds" in res_at[1]

    # Well above threshold -> Fires
    res_above = rule_large_amount(Decimal("3500.00"), threshold=threshold, points=points)
    assert res_above is not None
    assert res_above[0] == 40


def test_rule_high_velocity_boundary() -> None:
    """Boundary test: HIGH_VELOCITY triggers at transfer count > threshold."""
    threshold = 3
    points = 35

    # Below threshold -> None
    assert rule_high_velocity(2, threshold_count=threshold, points=points) is None

    # Exactly at threshold -> None (rule is "more than N transfers")
    assert rule_high_velocity(3, threshold_count=threshold, points=points) is None

    # Just above threshold -> Fires
    res_above = rule_high_velocity(4, threshold_count=threshold, points=points)
    assert res_above is not None
    assert res_above[0] == 35
    assert "exceeds limit" in res_above[1]


def test_rule_new_recipient_large_boundary() -> None:
    """Boundary test: NEW_RECIPIENT_LARGE triggers on first transfer AND amount >= threshold."""
    threshold = Decimal("500.00")
    points = 30

    # First transfer, but just below threshold -> None
    assert rule_new_recipient_large(
        is_first_transfer=True,
        amount=Decimal("499.99"),
        threshold=threshold,
        points=points,
    ) is None

    # First transfer, exactly at threshold -> Fires
    res_at = rule_new_recipient_large(
        is_first_transfer=True,
        amount=Decimal("500.00"),
        threshold=threshold,
        points=points,
    )
    assert res_at is not None
    assert res_at[0] == 30
    assert "First-time transfer" in res_at[1]

    # NOT first transfer, even with huge amount -> None
    assert rule_new_recipient_large(
        is_first_transfer=False,
        amount=Decimal("5000.00"),
        threshold=threshold,
        points=points,
    ) is None


def test_rule_near_limit_boundary() -> None:
    """Boundary test: NEAR_LIMIT triggers when amount is within 10% of single limit (>= 0.90 * limit)."""
    single_limit = Decimal("5000.00")
    percent = Decimal("0.90")  # 90% of 5000 = 4500.00
    points = 25

    # Just below 90% of limit -> None
    assert rule_near_limit(
        amount=Decimal("4499.99"),
        single_limit=single_limit,
        percent_threshold=percent,
        points=points,
    ) is None

    # Exactly at 90% of limit -> Fires
    res_at = rule_near_limit(
        amount=Decimal("4500.00"),
        single_limit=single_limit,
        percent_threshold=percent,
        points=points,
    )
    assert res_at is not None
    assert res_at[0] == 25
    assert "within 10% of single transfer limit" in res_at[1]

    # Above 90% of limit -> Fires
    res_above = rule_near_limit(
        amount=Decimal("4900.00"),
        single_limit=single_limit,
        percent_threshold=percent,
        points=points,
    )
    assert res_above is not None
    assert res_above[0] == 25


def test_rule_new_account_boundary() -> None:
    """Boundary test: NEW_ACCOUNT triggers when account age is less than threshold days."""
    now = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
    threshold_days = 30
    points = 20

    # Account created 30 days ago -> Not new (>= 30 days) -> None
    created_30_days_ago = now - timedelta(days=30)
    assert rule_new_account(
        created_30_days_ago,
        threshold_days=threshold_days,
        points=points,
        current_time=now,
    ) is None

    # Account created 31 days ago -> Not new -> None
    created_31_days_ago = now - timedelta(days=31)
    assert rule_new_account(
        created_31_days_ago,
        threshold_days=threshold_days,
        points=points,
        current_time=now,
    ) is None

    # Account created 29 days ago -> New (< 30 days) -> Fires
    created_29_days_ago = now - timedelta(days=29)
    res_new = rule_new_account(
        created_29_days_ago,
        threshold_days=threshold_days,
        points=points,
        current_time=now,
    )
    assert res_new is not None
    assert res_new[0] == 20
    assert "Sender account is new" in res_new[1]


def test_risk_level_thresholds_and_capping() -> None:
    """Verify 0-29 LOW, 30-59 MEDIUM, 60-100 HIGH thresholds."""
    assert compute_risk_level(0) == RiskLevel.LOW
    assert compute_risk_level(29) == RiskLevel.LOW
    assert compute_risk_level(30) == RiskLevel.MEDIUM
    assert compute_risk_level(59) == RiskLevel.MEDIUM
    assert compute_risk_level(60) == RiskLevel.HIGH
    assert compute_risk_level(100) == RiskLevel.HIGH
    assert compute_risk_level(150) == RiskLevel.HIGH
