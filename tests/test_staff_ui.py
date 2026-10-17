"""
SentinelPay – Tests for Staff UI Endpoints (Prompt 0).

Covers:
  - GET /admin/overview:
      - Role checks (Customer 403, unauthenticated 401, Risk Analyst 200, Admin 200)
      - Counts: transactions_today, transactions_yesterday, held_for_review,
        open_recon_exceptions, open_disputes, overdue_disputes
      - 7-day daily_volume series: [{date, count, total_amount}] with string amounts
      - payments_by_status breakdown
      - risk_level_distribution breakdown
  - GET /staff/transactions:
      - Role checks (Customer 403, unauthenticated 401, Risk Analyst 200, Admin 200)
      - Risk indicator exposure (risk_score, risk_level included for staff)
      - Pagination structure (page, page_size, total, pages, items)
      - Filters: status, risk_level, min_amount, max_amount, date range, search by transaction_ref
      - Newest first ordering (created_at desc)
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import uuid

import pytest
from conftest import TestSession, client

from app.accounts.models import Account, AccountStatus, AccountType
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.disputes.models import Dispute, DisputeCategory, DisputeStatus
from app.fraud.models import AlertStatus, FraudAlert, RiskLevel
from app.payments.models import Payment, PaymentStatus
from app.recon.models import ExceptionStatus, ExceptionType, ReconciliationException, ReconciliationRun
from app.transactions.models import Transaction, TransactionStatus


def _create_user(
    email: str,
    role: UserRole = UserRole.CUSTOMER,
    password: str = "Password123!",
) -> tuple[int, str]:
    """Helper: create user in DB and return (user_id, 'Bearer <token>')."""
    with TestSession() as db:
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name=f"User {email}",
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id

    res = client.post("/auth/login", data={"username": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    token = res.json()["access_token"]
    return user_id, f"Bearer {token}"


def _create_account(user_id: int, balance: str = "5000.00") -> int:
    """Helper: create a funded checking account."""
    with TestSession() as db:
        acc = Account(
            user_id=user_id,
            account_number=f"{uuid.uuid4().int % 10**10:010d}",
            account_type=AccountType.CHECKING,
            balance=Decimal(balance),
            status=AccountStatus.ACTIVE,
        )
        db.add(acc)
        db.commit()
        db.refresh(acc)
        return acc.id


# ─────────────────────────────────────────────────────────────
# 1. GET /admin/overview Tests
# ─────────────────────────────────────────────────────────────

def test_admin_overview_role_checks() -> None:
    """Customer gets 403, unauthenticated gets 401, Admin and Risk Analyst get 200."""
    uid = uuid.uuid4().hex[:6]
    _, customer_token = _create_user(f"cust_ov_{uid}@example.com", UserRole.CUSTOMER)
    _, analyst_token = _create_user(f"analyst_ov_{uid}@example.com", UserRole.RISK_ANALYST)
    _, admin_token = _create_user(f"admin_ov_{uid}@example.com", UserRole.ADMIN)

    # 1. Unauthenticated -> 401
    res = client.get("/admin/overview")
    assert res.status_code == 401

    # 2. Customer -> 403
    res = client.get("/admin/overview", headers={"Authorization": customer_token})
    assert res.status_code == 403

    # 3. Risk Analyst -> 200
    res = client.get("/admin/overview", headers={"Authorization": analyst_token})
    assert res.status_code == 200

    # 4. Admin -> 200
    res = client.get("/admin/overview", headers={"Authorization": admin_token})
    assert res.status_code == 200


def test_admin_overview_counts_and_series() -> None:
    """Verify exact response keys, series format, and accurate aggregation metrics."""
    uid = uuid.uuid4().hex[:6]
    _, admin_token = _create_user(f"admin_metrics_{uid}@example.com", UserRole.ADMIN)
    cust_id, _ = _create_user(f"cust_metrics_{uid}@example.com", UserRole.CUSTOMER)
    acc1_id = _create_account(cust_id, "10000.00")
    acc2_id = _create_account(cust_id, "10000.00")

    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    with TestSession() as db:
        # Seed 1 transaction today ($150.00)
        tx_today = Transaction(
            transaction_ref=f"TX-TODAY-{uid}",
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("150.00"),
            status=TransactionStatus.COMPLETED,
            risk_score=10,
            risk_level=RiskLevel.LOW,
            created_at=now,
        )
        # Seed 1 transaction yesterday ($250.00)
        tx_yesterday = Transaction(
            transaction_ref=f"TX-YEST-{uid}",
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("250.00"),
            status=TransactionStatus.COMPLETED,
            risk_score=45,
            risk_level=RiskLevel.MEDIUM,
            created_at=yesterday,
        )
        db.add_all([tx_today, tx_yesterday])
        db.flush()

        # Seed Fraud Alerts: 1 OPEN (HIGH risk), 1 RESOLVED (LOW risk)
        alert_open = FraudAlert(
            transaction_id=tx_today.id,
            risk_score=75,
            risk_level=RiskLevel.HIGH,
            triggered_rules=[{"rule": "LARGE_AMOUNT", "points": 40, "reason": "Test"}],
            status=AlertStatus.OPEN,
        )
        alert_resolved = FraudAlert(
            transaction_id=tx_yesterday.id,
            risk_score=15,
            risk_level=RiskLevel.LOW,
            triggered_rules=[],
            status=AlertStatus.RESOLVED,
        )
        db.add_all([alert_open, alert_resolved])

        # Seed Recon Exceptions: 1 OPEN, 1 RESOLVED
        recon_run = ReconciliationRun(
            started_by=cust_id,
            payments_checked=1,
            rail_records_checked=1,
            exceptions_found=2,
            exceptions_new=2,
        )
        db.add(recon_run)
        db.flush()

        recon_open = ReconciliationException(
            run_id=recon_run.id,
            exception_type=ExceptionType.MISSING_AT_BILLER,
            status=ExceptionStatus.OPEN,
            rail_reference=f"RAIL-{uid}-1",
            details={"note": "test"},
        )
        recon_resolved = ReconciliationException(
            run_id=recon_run.id,
            exception_type=ExceptionType.AMOUNT_MISMATCH,
            status=ExceptionStatus.RESOLVED,
            rail_reference=f"RAIL-{uid}-2",
            details={"note": "resolved"},
        )
        db.add_all([recon_open, recon_resolved])

        # Seed Disputes: 1 OPEN (not overdue), 1 OVERDUE (due 2 hours ago), 1 RESOLVED
        dispute_open = Dispute(
            case_ref=f"DSP-OPN-{uid}",
            user_id=cust_id,
            category=DisputeCategory.DUPLICATE_DEBIT,
            description="Open test dispute",
            status=DisputeStatus.OPEN,
            sla_due_at=now + timedelta(hours=24),
        )
        dispute_overdue = Dispute(
            case_ref=f"DSP-OVD-{uid}",
            user_id=cust_id,
            category=DisputeCategory.UNAUTHORIZED,
            description="Overdue test dispute",
            status=DisputeStatus.OPEN,
            sla_due_at=now - timedelta(hours=2),
        )
        dispute_resolved = Dispute(
            case_ref=f"DSP-RES-{uid}",
            user_id=cust_id,
            category=DisputeCategory.OTHER,
            description="Resolved test dispute",
            status=DisputeStatus.RESOLVED_REFUNDED,
            sla_due_at=now - timedelta(hours=5),
        )
        db.add_all([dispute_open, dispute_overdue, dispute_resolved])

        # Seed Payment: 1 SETTLED, 1 UNKNOWN
        pmt_settled = Payment(
            payment_ref=f"PMT-SET-{uid}",
            user_id=cust_id,
            sender_account_id=acc1_id,
            biller_code="ELECTRIC_CO",
            rail_reference=f"RAIL-SET-{uid}",
            amount=Decimal("75.00"),
            status=PaymentStatus.SETTLED,
        )
        pmt_unknown = Payment(
            payment_ref=f"PMT-UNK-{uid}",
            user_id=cust_id,
            sender_account_id=acc1_id,
            biller_code="WATER_UTIL",
            rail_reference=f"RAIL-UNK-{uid}",
            amount=Decimal("45.00"),
            status=PaymentStatus.UNKNOWN,
        )
        db.add_all([pmt_settled, pmt_unknown])
        db.commit()

    res = client.get("/admin/overview", headers={"Authorization": admin_token})
    assert res.status_code == 200
    data = res.json()

    # Check top-level keys
    assert "transactions_today" in data
    assert "transactions_yesterday" in data
    assert "held_for_review" in data
    assert "open_recon_exceptions" in data
    assert "open_disputes" in data
    assert "overdue_disputes" in data
    assert "payments_by_status" in data
    assert "daily_volume" in data
    assert "risk_level_distribution" in data

    # Verify counts reflect at least our seeded records
    assert data["transactions_today"] >= 1
    assert data["transactions_yesterday"] >= 1
    assert data["held_for_review"] >= 1
    assert data["open_recon_exceptions"] >= 1
    assert data["open_disputes"] >= 2  # open and overdue are both OPEN status
    assert data["overdue_disputes"] >= 1

    # Verify daily_volume has exactly 7 days
    assert len(data["daily_volume"]) == 7
    for item in data["daily_volume"]:
        assert "date" in item
        assert "count" in item
        assert "total_amount" in item
        assert isinstance(item["count"], int)
        assert isinstance(item["total_amount"], str)
        assert "." in item["total_amount"]  # Valid formatted decimal string

    # Verify payments_by_status has all status keys
    assert "PROCESSING" in data["payments_by_status"]
    assert "SETTLED" in data["payments_by_status"]
    assert "UNKNOWN" in data["payments_by_status"]
    assert "FAILED" in data["payments_by_status"]
    assert "REVERSED" in data["payments_by_status"]
    assert "NEEDS_INVESTIGATION" in data["payments_by_status"]
    assert data["payments_by_status"]["SETTLED"] >= 1
    assert data["payments_by_status"]["UNKNOWN"] >= 1

    # Verify risk_level_distribution
    assert "low" in data["risk_level_distribution"]
    assert "medium" in data["risk_level_distribution"]
    assert "high" in data["risk_level_distribution"]
    assert data["risk_level_distribution"]["high"] >= 1


# ─────────────────────────────────────────────────────────────
# 2. GET /staff/transactions Tests
# ─────────────────────────────────────────────────────────────

def test_staff_transactions_role_checks() -> None:
    """Customer gets 403, unauthenticated gets 401, Risk Analyst and Admin get 200."""
    uid = uuid.uuid4().hex[:6]
    _, customer_token = _create_user(f"cust_txs_{uid}@example.com", UserRole.CUSTOMER)
    _, analyst_token = _create_user(f"analyst_txs_{uid}@example.com", UserRole.RISK_ANALYST)
    _, admin_token = _create_user(f"admin_txs_{uid}@example.com", UserRole.ADMIN)

    # 1. Unauthenticated -> 401
    res = client.get("/staff/transactions")
    assert res.status_code == 401

    # 2. Customer -> 403
    res = client.get("/staff/transactions", headers={"Authorization": customer_token})
    assert res.status_code == 403

    # 3. Risk Analyst -> 200
    res = client.get("/staff/transactions", headers={"Authorization": analyst_token})
    assert res.status_code == 200

    # 4. Admin -> 200
    res = client.get("/staff/transactions", headers={"Authorization": admin_token})
    assert res.status_code == 200


def test_staff_transactions_includes_risk_indicators_and_pagination() -> None:
    """Response returns risk_score and risk_level along with standard pagination fields."""
    uid = uuid.uuid4().hex[:6]
    _, admin_token = _create_user(f"admin_tx_page_{uid}@example.com", UserRole.ADMIN)
    cust_id, _ = _create_user(f"cust_tx_page_{uid}@example.com", UserRole.CUSTOMER)
    acc1_id = _create_account(cust_id, "5000.00")
    acc2_id = _create_account(cust_id, "5000.00")

    ref = f"TX-RISK-{uid}"
    with TestSession() as db:
        tx = Transaction(
            transaction_ref=ref,
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("1200.00"),
            status=TransactionStatus.PENDING_REVIEW,
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            description="Suspicious flagged transfer",
            created_at=datetime.now(timezone.utc),
        )
        db.add(tx)
        db.commit()

    res = client.get(
        f"/staff/transactions?transaction_ref={ref}",
        headers={"Authorization": admin_token},
    )
    assert res.status_code == 200
    data = res.json()

    # Pagination wrapper
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert "pages" in data

    assert data["total"] == 1
    item = data["items"][0]
    assert item["transaction_ref"] == ref
    assert item["amount"] == "1200.00"
    assert item["status"] == "pending_review"
    assert item["risk_score"] == 65
    assert item["risk_level"] == "high"


def test_staff_transactions_filters() -> None:
    """Filters by status, risk_level, amount bounds, date range, and ref search work accurately."""
    uid = uuid.uuid4().hex[:6]
    _, analyst_token = _create_user(f"analyst_flt_{uid}@example.com", UserRole.RISK_ANALYST)
    cust_id, _ = _create_user(f"cust_flt_{uid}@example.com", UserRole.CUSTOMER)
    acc1_id = _create_account(cust_id, "20000.00")
    acc2_id = _create_account(cust_id, "20000.00")

    base_time = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    with TestSession() as db:
        tx1 = Transaction(
            transaction_ref=f"TX-FLT1-{uid}",
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("50.00"),
            status=TransactionStatus.COMPLETED,
            risk_score=10,
            risk_level=RiskLevel.LOW,
            created_at=base_time,
        )
        tx2 = Transaction(
            transaction_ref=f"TX-FLT2-{uid}",
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("500.00"),
            status=TransactionStatus.PENDING_REVIEW,
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            created_at=base_time + timedelta(hours=1),
        )
        tx3 = Transaction(
            transaction_ref=f"TX-FLT3-{uid}",
            sender_account_id=acc1_id,
            recipient_account_id=acc2_id,
            amount=Decimal("2000.00"),
            status=TransactionStatus.REJECTED,
            risk_score=85,
            risk_level=RiskLevel.HIGH,
            created_at=base_time + timedelta(hours=2),
        )
        db.add_all([tx1, tx2, tx3])
        db.commit()

    headers = {"Authorization": analyst_token}

    # 1. Filter by status: COMPLETED
    res = client.get(f"/staff/transactions?transaction_ref=TX-FLT&status=completed", headers=headers)
    assert res.status_code == 200
    refs = [t["transaction_ref"] for t in res.json()["items"] if uid in t["transaction_ref"]]
    assert refs == [f"TX-FLT1-{uid}"]

    # 2. Filter by risk_level: high
    res = client.get(f"/staff/transactions?transaction_ref=TX-FLT&risk_level=high", headers=headers)
    assert res.status_code == 200
    refs = [t["transaction_ref"] for t in res.json()["items"] if uid in t["transaction_ref"]]
    assert set(refs) == {f"TX-FLT2-{uid}", f"TX-FLT3-{uid}"}

    # 3. Filter by min_amount and max_amount (between $100 and $1000)
    res = client.get(
        f"/staff/transactions?transaction_ref=TX-FLT&min_amount=100.00&max_amount=1000.00",
        headers=headers,
    )
    assert res.status_code == 200
    refs = [t["transaction_ref"] for t in res.json()["items"] if uid in t["transaction_ref"]]
    assert refs == [f"TX-FLT2-{uid}"]

    # 4. Filter by date range (between base_time + 30 min and base_time + 90 min)
    start_iso = (base_time + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = (base_time + timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = client.get(
        f"/staff/transactions?transaction_ref=TX-FLT&from_date={start_iso}&to_date={end_iso}",
        headers=headers,
    )
    assert res.status_code == 200
    refs = [t["transaction_ref"] for t in res.json()["items"] if uid in t["transaction_ref"]]
    assert refs == [f"TX-FLT2-{uid}"]

    # 5. Ordering: newest first (TX-FLT3 was created at +2h, TX-FLT2 at +1h, TX-FLT1 at 0h)
    res = client.get(f"/staff/transactions?transaction_ref=TX-FLT", headers=headers)
    assert res.status_code == 200
    refs = [t["transaction_ref"] for t in res.json()["items"] if uid in t["transaction_ref"]]
    assert refs == [f"TX-FLT3-{uid}", f"TX-FLT2-{uid}", f"TX-FLT1-{uid}"]
