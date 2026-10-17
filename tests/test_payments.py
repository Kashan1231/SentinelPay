"""
SentinelPay – Test suite for Phase 8: Simulated External Payment Rail.

Tests cover:
  20. OK biller: balance debited once, status SETTLED, rail record exists.
  21. DECLINE biller: debited then refunded, status REVERSED, final balance unchanged, timeline shows steps.
  22. TIMEOUT_AFTER_PROCESS: status UNKNOWN, balance debited, no refund; after sweep status SETTLED, no refund.
  23. TIMEOUT_BEFORE_PROCESS: UNKNOWN; sweep increments attempts until max, then FAILED and REVERSED with exactly one refund.
  24. Crash simulation: create a payment left in PROCESSING (as if server died after step 1); sweep recovers it correctly.
  25. Replaying the same Idempotency-Key never double-debits.
  26. Running the sweep twice, or two concurrent sweeps, never refunds twice.
  27. Late SETTLED after REVERSED lands in NEEDS_INVESTIGATION.
  28. Customer cannot see another customer's payment (403) and never sees failure_mode.
  29. Every state change has a PaymentEvent and an audit row, and /audit/verify is still valid.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.accounts.models import Account, AccountStatus, AccountType
from app.audit.models import AuditLog
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.payments.models import Payment, PaymentEvent, PaymentStatus
from app.payments.recovery import handle_late_settlement, resolve_unknown, sweep_stuck_payments
from app.rail.models import FailureMode, RailBiller, RailRecord, RailRecordStatus
from conftest import TestSession, client


def create_user_with_token(
    email: str,
    password: str = "Password123!",
    role: UserRole = UserRole.CUSTOMER,
) -> tuple[int, str]:
    """Helper: create user and return (user_id, 'Bearer <token>')."""
    with TestSession() as db:
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name="Payment Tester",
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        uid = user.id

    login_resp = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert login_resp.status_code == 200, login_resp.text
    token = login_resp.json()["access_token"]
    return uid, f"Bearer {token}"


def create_account(user_id: int, account_number: str, balance: Decimal) -> int:
    """Helper: create active account with given balance."""
    with TestSession() as db:
        acc = Account(
            user_id=user_id,
            account_number=account_number,
            account_type=AccountType.CHECKING,
            balance=balance,
            status=AccountStatus.ACTIVE,
        )
        db.add(acc)
        db.commit()
        db.refresh(acc)
        return acc.id


def ensure_biller(code: str, name: str, failure_mode: FailureMode) -> None:
    """Helper: create or update a mock rail biller."""
    with TestSession() as db:
        stmt = select(RailBiller).where(RailBiller.code == code)
        biller = db.scalar(stmt)
        if biller:
            biller.failure_mode = failure_mode
            biller.is_active = True
        else:
            biller = RailBiller(
                code=code,
                name=name,
                failure_mode=failure_mode,
                is_active=True,
            )
            db.add(biller)
        db.commit()


# ─────────────────────────────────────────────────────────────
# TEST 20: OK Biller
# ─────────────────────────────────────────────────────────────
def test_20_ok_biller_payment_success():
    """20. OK biller: balance debited once, status SETTLED, rail record exists."""
    ensure_biller("ELEC_OK", "Electric Utility", FailureMode.OK)
    uid, token = create_user_with_token("cust_ok@example.com")
    acc_id = create_account(uid, "1000000020", Decimal("1000.00"))

    resp = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": "IDEMP-20-TEST"},
        json={"biller_code": "ELEC_OK", "amount": "150.00", "sender_account_id": acc_id},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "SETTLED"
    assert data["status_message"] == "Your payment has been confirmed by the biller."

    # Balance debited exactly once
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("850.00")

        pay = db.get(Payment, data["id"])
        assert pay.status == PaymentStatus.SETTLED

        # Rail record exists on the biller's side
        record = db.scalar(select(RailRecord).where(RailRecord.rail_reference == pay.rail_reference))
        assert record is not None
        assert record.status == RailRecordStatus.SETTLED
        assert record.amount == Decimal("150.00")


# ─────────────────────────────────────────────────────────────
# TEST 21: DECLINE Biller
# ─────────────────────────────────────────────────────────────
def test_21_decline_biller_payment_reversal():
    """21. DECLINE biller: debited then refunded, status REVERSED, final balance unchanged, timeline shows steps."""
    ensure_biller("GAS_DECLINE", "Gas Corp", FailureMode.DECLINE)
    uid, token = create_user_with_token("cust_decl@example.com")
    acc_id = create_account(uid, "1000000021", Decimal("1000.00"))

    resp = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": "IDEMP-21-TEST"},
        json={"biller_code": "GAS_DECLINE", "amount": "200.00", "sender_account_id": acc_id},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "REVERSED"

    # Final balance unchanged (debited then refunded back to 1000.00)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("1000.00")

        pay = db.get(Payment, data["id"])
        assert pay.status == PaymentStatus.REVERSED

        # Rail record shows FAILED
        record = db.scalar(select(RailRecord).where(RailRecord.rail_reference == pay.rail_reference))
        assert record is not None
        assert record.status == RailRecordStatus.FAILED

    # Timeline shows transitions: PROCESSING -> FAILED -> REVERSED
    detail_resp = client.get(f"/payments/{data['id']}", headers={"Authorization": token})
    assert detail_resp.status_code == 200
    timeline = detail_resp.json()["timeline"]
    statuses = [e["to_status"] for e in timeline]
    assert "PROCESSING" in statuses
    assert "FAILED" in statuses
    assert "REVERSED" in statuses


# ─────────────────────────────────────────────────────────────
# TEST 22: TIMEOUT_AFTER_PROCESS
# ─────────────────────────────────────────────────────────────
def test_22_timeout_after_process_recovered_to_settled():
    """22. TIMEOUT_AFTER_PROCESS: status UNKNOWN, balance debited, no refund; after sweep status SETTLED, no refund."""
    ensure_biller("WATER_TOA", "Water Co", FailureMode.TIMEOUT_AFTER_PROCESS)
    uid, token = create_user_with_token("cust_toa@example.com")
    _, admin_token = create_user_with_token("admin_toa@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000022", Decimal("1000.00"))

    resp = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": "IDEMP-22-TEST"},
        json={"biller_code": "WATER_TOA", "amount": "100.00", "sender_account_id": acc_id},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "UNKNOWN"

    # Debited, no refund yet
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("900.00")

        # Age the payment so sweep picks it up
        pay = db.get(Payment, data["id"])
        pay.updated_at = datetime.now(timezone.utc) - timedelta(seconds=200)
        db.commit()

    # Admin sweep
    sweep_resp = client.post("/admin/payments/sweep", headers={"Authorization": admin_token})
    assert sweep_resp.status_code == 200
    assert sweep_resp.json()["resolved"] >= 1

    # Status is now SETTLED, balance remains 900.00 (no refund)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("900.00")
        pay = db.get(Payment, data["id"])
        assert pay.status == PaymentStatus.SETTLED


# ─────────────────────────────────────────────────────────────
# TEST 23: TIMEOUT_BEFORE_PROCESS
# ─────────────────────────────────────────────────────────────
def test_23_timeout_before_process_recovered_with_refund():
    """23. TIMEOUT_BEFORE_PROCESS: UNKNOWN; sweep increments attempts until max, then FAILED and REVERSED with exactly one refund."""
    ensure_biller("NET_TOB", "Internet Provider", FailureMode.TIMEOUT_BEFORE_PROCESS)
    uid, token = create_user_with_token("cust_tob@example.com")
    _, admin_token = create_user_with_token("admin_tob@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000023", Decimal("1000.00"))

    resp = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": "IDEMP-23-TEST"},
        json={"biller_code": "NET_TOB", "amount": "100.00", "sender_account_id": acc_id},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "UNKNOWN"

    # Balance debited
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("900.00")

    # Inquiries 1 and 2: stay UNKNOWN, attempts incremented
    for expected_attempt in (1, 2):
        with TestSession() as db:
            pay = db.get(Payment, data["id"])
            pay.updated_at = datetime.now(timezone.utc) - timedelta(seconds=200)
            db.commit()

        client.post("/admin/payments/sweep", headers={"Authorization": admin_token})

        with TestSession() as db:
            pay = db.get(Payment, data["id"])
            assert pay.status == PaymentStatus.UNKNOWN
            assert pay.attempts_count == expected_attempt
            acc = db.get(Account, acc_id)
            assert acc.balance == Decimal("900.00")

    # Inquiry 3 (reaches max inquiries = 3): moves to FAILED then REVERSED with refund
    with TestSession() as db:
        pay = db.get(Payment, data["id"])
        pay.updated_at = datetime.now(timezone.utc) - timedelta(seconds=200)
        db.commit()

    client.post("/admin/payments/sweep", headers={"Authorization": admin_token})

    with TestSession() as db:
        pay = db.get(Payment, data["id"])
        assert pay.status == PaymentStatus.REVERSED
        assert pay.attempts_count == 3
        # Exactly one refund issued: balance back to 1000.00
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("1000.00")


# ─────────────────────────────────────────────────────────────
# TEST 24: Crash simulation
# ─────────────────────────────────────────────────────────────
def test_24_crash_simulation_stuck_processing_recovered():
    """24. Crash simulation: create a payment left in PROCESSING (as if server died after step 1); sweep recovers it correctly."""
    ensure_biller("ELEC_OK", "Electric Utility", FailureMode.OK)
    uid, _ = create_user_with_token("cust_crash@example.com")
    _, admin_token = create_user_with_token("admin_crash@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000024", Decimal("500.00"))

    # Simulate crash: Step 1 completed (debited 100.00, left in PROCESSING), server crashed before Step 2/3
    stuck_time = datetime.now(timezone.utc) - timedelta(seconds=300)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        acc.balance -= Decimal("100.00")

        pay = Payment(
            payment_ref="PAY-CRASH000001",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_OK",
            amount=Decimal("100.00"),
            status=PaymentStatus.PROCESSING,
            rail_reference="RAIL-CRASH000001",
            attempts_count=2,  # set attempts to 2 so next NOT_FOUND triggers refund
            created_at=stuck_time,
            updated_at=stuck_time,
        )
        db.add(pay)
        db.commit()
        pay_id = pay.id

    # Sweep recovers the stuck PROCESSING payment
    sweep_resp = client.post("/admin/payments/sweep", headers={"Authorization": admin_token})
    assert sweep_resp.status_code == 200

    # Verify payment was recovered to REVERSED with refund
    with TestSession() as db:
        pay = db.get(Payment, pay_id)
        assert pay.status == PaymentStatus.REVERSED
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("500.00")  # Funds safely refunded back


# ─────────────────────────────────────────────────────────────
# TEST 25: Idempotency replay
# ─────────────────────────────────────────────────────────────
def test_25_idempotency_replay_never_double_debits():
    """25. Replaying the same Idempotency-Key never double-debits."""
    ensure_biller("ELEC_OK", "Electric Utility", FailureMode.OK)
    uid, token = create_user_with_token("cust_idemp@example.com")
    acc_id = create_account(uid, "1000000025", Decimal("1000.00"))

    idemp_key = "KEY-IDEMP-TEST-25"
    payload = {"biller_code": "ELEC_OK", "amount": "150.00", "sender_account_id": acc_id}

    # First request
    resp1 = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": idemp_key},
        json=payload,
    )
    assert resp1.status_code == 201

    # Balance dropped to 850.00
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("850.00")

    # Replay identical request
    resp2 = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": idemp_key},
        json=payload,
    )
    assert resp2.status_code == 201
    assert resp2.json()["id"] == resp1.json()["id"]

    # Balance remains 850.00 (NEVER double-debited)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("850.00")

        # Verify IDEMPOTENT_REPLAY audit log was written
        replays = db.scalars(
            select(AuditLog).where(AuditLog.event_type == "IDEMPOTENT_REPLAY")
        ).all()
        assert len(replays) >= 1


# ─────────────────────────────────────────────────────────────
# TEST 26: Sweep concurrency
# ─────────────────────────────────────────────────────────────
def test_26_sweep_concurrency_never_refunds_twice():
    """26. Running the sweep twice, or two concurrent sweeps, never refunds twice."""
    uid, _ = create_user_with_token("cust_conc@example.com")
    acc_id = create_account(uid, "1000000026", Decimal("900.00"))

    # Create a payment in UNKNOWN ready for final inquiry/refund
    stuck_time = datetime.now(timezone.utc) - timedelta(seconds=300)
    with TestSession() as db:
        pay = Payment(
            payment_ref="PAY-CONC0000001",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="NET_TOB",
            amount=Decimal("100.00"),
            status=PaymentStatus.UNKNOWN,
            rail_reference="RAIL-CONC0000001",
            attempts_count=2,  # will hit max on this sweep
            created_at=stuck_time,
            updated_at=stuck_time,
        )
        db.add(pay)
        db.commit()
        pay_id = pay.id

    # Run two sweeps concurrently
    def run_sweep():
        with TestSession() as db:
            return sweep_stuck_payments(db)

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_sweep)
        f2 = executor.submit(run_sweep)
        f1.result()
        f2.result()

    # Balance must be refunded exactly once (900 + 100 = 1000), never twice (1100)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("1000.00")
        pay = db.get(Payment, pay_id)
        assert pay.status == PaymentStatus.REVERSED


# ─────────────────────────────────────────────────────────────
# TEST 27: Late SETTLED after REVERSED
# ─────────────────────────────────────────────────────────────
def test_27_late_settled_after_reversed_lands_in_needs_investigation():
    """27. Late SETTLED after REVERSED lands in NEEDS_INVESTIGATION."""
    uid, _ = create_user_with_token("cust_late@example.com")
    acc_id = create_account(uid, "1000000027", Decimal("1000.00"))

    # A payment that was already reversed (refunded)
    with TestSession() as db:
        pay = Payment(
            payment_ref="PAY-LATE0000001",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="WATER_TOA",
            amount=Decimal("100.00"),
            status=PaymentStatus.REVERSED,
            rail_reference="RAIL-LATE0000001",
            attempts_count=3,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(pay)
        db.commit()
        pay_id = pay.id

        # Later, biller reports SETTLED on the rail
        ensure_biller("WATER_TOA", "Water Co", FailureMode.OK)
        biller = db.scalar(select(RailBiller).where(RailBiller.code == "WATER_TOA"))
        rail_rec = RailRecord(
            rail_reference="RAIL-LATE0000001",
            biller_id=biller.id,
            amount=Decimal("100.00"),
            status=RailRecordStatus.SETTLED,
        )
        db.add(rail_rec)
        db.commit()

        # Run resolution
        resolve_unknown(db, pay_id)
        db.commit()

    # Verify status is now NEEDS_INVESTIGATION
    with TestSession() as db:
        pay = db.get(Payment, pay_id)
        assert pay.status == PaymentStatus.NEEDS_INVESTIGATION

        # Check audit event exists
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.event_type == "PAYMENT_NEEDS_INVESTIGATION",
                AuditLog.entity_id == str(pay_id),
            )
        )
        assert audit is not None
        assert audit.outcome == "SUCCESS"


# ─────────────────────────────────────────────────────────────
# TEST 28: Customer isolation & visibility
# ─────────────────────────────────────────────────────────────
def test_28_payment_visibility_and_customer_isolation():
    """28. Customer cannot see another customer's payment (403) and never sees failure_mode."""
    ensure_biller("ELEC_OK", "Electric Utility", FailureMode.OK)
    uid_a, token_a = create_user_with_token("cust_a@example.com")
    _, token_b = create_user_with_token("cust_b@example.com")
    _, admin_token = create_user_with_token("admin_vis@example.com", role=UserRole.ADMIN)
    acc_id_a = create_account(uid_a, "1000000028", Decimal("1000.00"))

    # Customer A creates payment
    resp = client.post(
        "/payments",
        headers={"Authorization": token_a, "Idempotency-Key": "IDEMP-28-TEST"},
        json={"biller_code": "ELEC_OK", "amount": "50.00", "sender_account_id": acc_id_a},
    )
    assert resp.status_code == 201
    pay_id = resp.json()["id"]

    # Customer B tries to view Customer A's payment -> 403 Forbidden
    resp_b = client.get(f"/payments/{pay_id}", headers={"Authorization": token_b})
    assert resp_b.status_code == 403

    # Customer A views their payment -> 200 OK
    resp_a = client.get(f"/payments/{pay_id}", headers={"Authorization": token_a})
    assert resp_a.status_code == 200
    data_a = resp_a.json()

    # Never sees failure_mode or rail internals
    assert "failure_mode" not in data_a
    assert "rail_reference" not in data_a

    # Admin can view Customer A's payment
    resp_admin = client.get(f"/payments/{pay_id}", headers={"Authorization": admin_token})
    assert resp_admin.status_code == 200


# ─────────────────────────────────────────────────────────────
# TEST 29: PaymentEvents and Audit hash chain integrity
# ─────────────────────────────────────────────────────────────
def test_29_state_changes_have_payment_events_and_audit_hash_chain_valid():
    """29. Every state change has a PaymentEvent and an audit row, and /audit/verify is still valid."""
    ensure_biller("ELEC_OK", "Electric Utility", FailureMode.OK)
    uid, token = create_user_with_token("cust_audit@example.com")
    _, admin_token = create_user_with_token("admin_audit@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000029", Decimal("1000.00"))

    resp = client.post(
        "/payments",
        headers={"Authorization": token, "Idempotency-Key": "IDEMP-29-TEST"},
        json={"biller_code": "ELEC_OK", "amount": "100.00", "sender_account_id": acc_id},
    )
    assert resp.status_code == 201
    pay_id = resp.json()["id"]

    with TestSession() as db:
        # Check PaymentEvents exist
        events = db.scalars(
            select(PaymentEvent).where(PaymentEvent.payment_id == pay_id)
        ).all()
        assert len(events) >= 2  # PROCESSING and SETTLED

        # Check audit rows exist
        audit_rows = db.scalars(
            select(AuditLog).where(
                AuditLog.entity_type == "payment",
                AuditLog.entity_id == str(pay_id),
            )
        ).all()
        assert len(audit_rows) >= 2  # PAYMENT_INITIATED and PAYMENT_SETTLED

    # Verify cryptographic hash chain remains 100% valid
    verify_resp = client.get("/audit/verify", headers={"Authorization": admin_token})
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["valid"] is True
    assert vdata["first_broken_id"] is None
