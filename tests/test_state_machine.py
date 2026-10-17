"""
Tests for the payment state machine (Phase 8 – Part C).
Verifies every allowed transition and a set of illegal transitions.
"""

import pytest
from sqlalchemy.orm import Session

from conftest import TestSession

from app.payments.models import Payment, PaymentEvent, PaymentStatus
from app.payments.state_machine import IllegalTransition, transition


def _make_payment(db: Session, status: PaymentStatus) -> Payment:
    """Helper: create a minimal payment row for state machine testing."""
    from datetime import datetime, timezone
    from decimal import Decimal
    from app.auth.models import User, UserRole
    from app.auth.security import hash_password
    from app.accounts.models import Account, AccountType, AccountStatus

    user = User(
        email="sm_test@example.com",
        full_name="SM Tester",
        hashed_password=hash_password("Test1Password!"),
        role=UserRole.CUSTOMER,
    )
    db.add(user)
    db.flush()

    account = Account(
        user_id=user.id,
        account_number="9999990001",
        account_type=AccountType.CHECKING,
        balance=Decimal("5000.00"),
        status=AccountStatus.ACTIVE,
    )
    db.add(account)
    db.flush()

    payment = Payment(
        payment_ref="PAY-SMTEST00001",
        user_id=user.id,
        sender_account_id=account.id,
        biller_code="TEST_BILLER",
        amount=Decimal("100.00"),
        status=status,
        rail_reference="RAIL-SMTEST00001",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(payment)
    db.flush()
    return payment


class TestAllowedTransitions:
    """Every legal state transition should succeed and produce a PaymentEvent."""

    @pytest.mark.parametrize("from_status,to_status", [
        (PaymentStatus.PROCESSING, PaymentStatus.SETTLED),
        (PaymentStatus.PROCESSING, PaymentStatus.FAILED),
        (PaymentStatus.PROCESSING, PaymentStatus.UNKNOWN),
        (PaymentStatus.UNKNOWN, PaymentStatus.SETTLED),
        (PaymentStatus.UNKNOWN, PaymentStatus.FAILED),
        (PaymentStatus.UNKNOWN, PaymentStatus.NEEDS_INVESTIGATION),
        (PaymentStatus.FAILED, PaymentStatus.REVERSED),
        (PaymentStatus.SETTLED, PaymentStatus.NEEDS_INVESTIGATION),
        (PaymentStatus.REVERSED, PaymentStatus.NEEDS_INVESTIGATION),
    ])
    def test_allowed_transition(self, from_status, to_status):
        db = TestSession()
        try:
            payment = _make_payment(db, from_status)
            event = transition(db, payment, to_status, "test note")
            db.flush()

            assert payment.status == to_status
            assert event.from_status == from_status.value
            assert event.to_status == to_status.value
            assert event.note == "test note"
        finally:
            db.rollback()
            db.close()


class TestIllegalTransitions:
    """Illegal state transitions must raise IllegalTransition."""

    @pytest.mark.parametrize("from_status,to_status", [
        (PaymentStatus.PROCESSING, PaymentStatus.REVERSED),
        (PaymentStatus.PROCESSING, PaymentStatus.NEEDS_INVESTIGATION),
        (PaymentStatus.SETTLED, PaymentStatus.PROCESSING),
        (PaymentStatus.SETTLED, PaymentStatus.FAILED),
        (PaymentStatus.SETTLED, PaymentStatus.REVERSED),
        (PaymentStatus.FAILED, PaymentStatus.SETTLED),
        (PaymentStatus.FAILED, PaymentStatus.PROCESSING),
        (PaymentStatus.REVERSED, PaymentStatus.PROCESSING),
        (PaymentStatus.REVERSED, PaymentStatus.SETTLED),
        (PaymentStatus.REVERSED, PaymentStatus.FAILED),
        (PaymentStatus.NEEDS_INVESTIGATION, PaymentStatus.PROCESSING),
        (PaymentStatus.NEEDS_INVESTIGATION, PaymentStatus.SETTLED),
    ])
    def test_illegal_transition(self, from_status, to_status):
        db = TestSession()
        try:
            payment = _make_payment(db, from_status)
            with pytest.raises(IllegalTransition):
                transition(db, payment, to_status)
        finally:
            db.rollback()
            db.close()
