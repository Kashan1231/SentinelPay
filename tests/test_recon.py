"""
SentinelPay – Test Suite for Phase 9 (Part A: Reconciliation).

Tests cover:
  1. Clean data: run finds zero exceptions.
  2. Detects all 5 mismatch types:
     - MISSING_AT_BILLER
     - ORPHAN_RAIL_RECORD
     - STATUS_MISMATCH
     - AMOUNT_MISMATCH
     - SUSPECTED_DUPLICATE
  3. Running twice does not duplicate open exceptions.
  4. In-flight young payments are skipped.
  5. Reconciliation changes no balances and no payment statuses.
  6. Resolve twice returns 409 Conflict.
  7. Role-based access control: customer gets 403 on all recon endpoints, risk analyst read-only.
  8. /audit/verify remains valid with all recon audit events logged.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.accounts.models import Account, AccountStatus, AccountType
from app.audit.models import AuditLog
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.payments.models import Payment, PaymentStatus
from app.rail.models import FailureMode, RailBiller, RailRecord, RailRecordStatus
from app.recon.models import ExceptionStatus, ExceptionType, ReconciliationException
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
            full_name="Recon Tester",
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


def ensure_biller(code: str, name: str, failure_mode: FailureMode = FailureMode.OK) -> int:
    """Helper: create or retrieve a mock rail biller."""
    with TestSession() as db:
        stmt = select(RailBiller).where(RailBiller.code == code)
        biller = db.scalar(stmt)
        if not biller:
            biller = RailBiller(
                code=code,
                name=name,
                failure_mode=failure_mode,
                is_active=True,
            )
            db.add(biller)
            db.commit()
            db.refresh(biller)
        return biller.id


# ─────────────────────────────────────────────────────────────
# 1. CLEAN DATA: ZERO EXCEPTIONS
# ─────────────────────────────────────────────────────────────
def test_recon_clean_data_zero_exceptions():
    """Clean data: run finds zero exceptions."""
    _, admin_token = create_user_with_token("admin_clean@example.com", role=UserRole.ADMIN)

    resp = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["exceptions_found"] == 0
    assert data["exceptions_new"] == 0
    assert data["payments_checked"] == 0
    assert data["rail_records_checked"] == 0


# ─────────────────────────────────────────────────────────────
# 2. DETECTS ALL 5 MISMATCH TYPES
# ─────────────────────────────────────────────────────────────
def test_recon_detects_all_mismatch_types():
    """Create each mismatch type and assert the correct exception type is raised."""
    uid, _ = create_user_with_token("cust_recon@example.com")
    _, admin_token = create_user_with_token("admin_mismatch@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000091", Decimal("5000.00"))
    biller_id = ensure_biller("ELEC_RECON", "Electric Utility")

    now = datetime.now(timezone.utc) - timedelta(minutes=10)

    with TestSession() as db:
        # 1. MISSING_AT_BILLER: Local SETTLED, no rail record
        p_missing = Payment(
            payment_ref="PAY-RECON-MISSING",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("100.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-RECON-MISSING",
            created_at=now,
            updated_at=now,
        )
        db.add(p_missing)

        # 2. ORPHAN_RAIL_RECORD: Rail SETTLED, no local payment
        r_orphan = RailRecord(
            rail_reference="RAIL-RECON-ORPHAN",
            biller_id=biller_id,
            amount=Decimal("200.00"),
            status=RailRecordStatus.SETTLED,
            created_at=now,
        )
        db.add(r_orphan)

        # 3. STATUS_MISMATCH: Local REVERSED, but rail SETTLED (money loss scenario)
        p_status = Payment(
            payment_ref="PAY-RECON-STATUS",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("150.00"),
            status=PaymentStatus.REVERSED,
            rail_reference="RAIL-RECON-STATUS",
            created_at=now,
            updated_at=now,
        )
        db.add(p_status)
        r_status = RailRecord(
            rail_reference="RAIL-RECON-STATUS",
            biller_id=biller_id,
            amount=Decimal("150.00"),
            status=RailRecordStatus.SETTLED,
            created_at=now,
        )
        db.add(r_status)

        # 4. AMOUNT_MISMATCH: Same reference, different amounts
        p_amount = Payment(
            payment_ref="PAY-RECON-AMOUNT",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("300.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-RECON-AMOUNT",
            created_at=now,
            updated_at=now,
        )
        db.add(p_amount)
        r_amount = RailRecord(
            rail_reference="RAIL-RECON-AMOUNT",
            biller_id=biller_id,
            amount=Decimal("350.00"),
            status=RailRecordStatus.SETTLED,
            created_at=now,
        )
        db.add(r_amount)

        # 5. SUSPECTED_DUPLICATE: Same user, biller, amount, 15 seconds apart
        p_dup1 = Payment(
            payment_ref="PAY-RECON-DUP1",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("50.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-RECON-DUP1",
            created_at=now,
            updated_at=now,
        )
        p_dup2 = Payment(
            payment_ref="PAY-RECON-DUP2",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("50.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-RECON-DUP2",
            created_at=now + timedelta(seconds=15),
            updated_at=now + timedelta(seconds=15),
        )
        db.add(p_dup1)
        db.add(p_dup2)
        r_dup1 = RailRecord(
            rail_reference="RAIL-RECON-DUP1",
            biller_id=biller_id,
            amount=Decimal("50.00"),
            status=RailRecordStatus.SETTLED,
            created_at=now,
        )
        r_dup2 = RailRecord(
            rail_reference="RAIL-RECON-DUP2",
            biller_id=biller_id,
            amount=Decimal("50.00"),
            status=RailRecordStatus.SETTLED,
            created_at=now + timedelta(seconds=15),
        )
        db.add(r_dup1)
        db.add(r_dup2)

        db.commit()

    # Trigger reconciliation
    resp = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp.status_code == 200
    run_data = resp.json()
    assert run_data["exceptions_found"] >= 5

    # Check that all 5 exception types exist in DB
    with TestSession() as db:
        exceptions = list(db.scalars(select(ReconciliationException)).all())
        found_types = {e.exception_type.value for e in exceptions}
        assert "MISSING_AT_BILLER" in found_types
        assert "ORPHAN_RAIL_RECORD" in found_types
        assert "STATUS_MISMATCH" in found_types
        assert "AMOUNT_MISMATCH" in found_types
        assert "SUSPECTED_DUPLICATE" in found_types


# ─────────────────────────────────────────────────────────────
# 3. RUNNING TWICE DOES NOT DUPLICATE OPEN EXCEPTIONS
# ─────────────────────────────────────────────────────────────
def test_recon_running_twice_does_not_duplicate_open_exceptions():
    """Running twice does not duplicate open exceptions."""
    uid, _ = create_user_with_token("cust_twice@example.com")
    _, admin_token = create_user_with_token("admin_twice@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000092", Decimal("1000.00"))
    ensure_biller("ELEC_RECON", "Electric Utility")

    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    with TestSession() as db:
        p = Payment(
            payment_ref="PAY-TWICE-01",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("100.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-TWICE-01",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()

    # First run: finds 1, new 1
    resp1 = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["exceptions_found"] == 1
    assert data1["exceptions_new"] == 1

    # Second run: finds 1, new 0
    resp2 = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["exceptions_found"] == 1
    assert data2["exceptions_new"] == 0

    with TestSession() as db:
        count = db.scalar(select(ReconciliationException).where(ReconciliationException.status == ExceptionStatus.OPEN))
        assert count is not None
        all_open = db.scalars(select(ReconciliationException).where(ReconciliationException.status == ExceptionStatus.OPEN)).all()
        assert len(all_open) == 1


# ─────────────────────────────────────────────────────────────
# 4. IN-FLIGHT YOUNG PAYMENTS ARE SKIPPED
# ─────────────────────────────────────────────────────────────
def test_recon_skips_inflight_young_payments():
    """In-flight young payments in PROCESSING or UNKNOWN are skipped."""
    uid, _ = create_user_with_token("cust_young@example.com")
    _, admin_token = create_user_with_token("admin_young@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000093", Decimal("1000.00"))
    ensure_biller("ELEC_RECON", "Electric Utility")

    # Payment created just 10 seconds ago in PROCESSING (no rail record yet)
    now = datetime.now(timezone.utc) - timedelta(seconds=10)
    with TestSession() as db:
        p = Payment(
            payment_ref="PAY-YOUNG-01",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("100.00"),
            status=PaymentStatus.PROCESSING,
            rail_reference="RAIL-YOUNG-01",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()

    resp = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp.status_code == 200
    data = resp.json()
    # In-flight payment is skipped, so 0 payments checked and 0 exceptions found
    assert data["payments_checked"] == 0
    assert data["exceptions_found"] == 0


# ─────────────────────────────────────────────────────────────
# 5. RECONCILIATION CHANGES NO BALANCES OR PAYMENT STATUSES
# ─────────────────────────────────────────────────────────────
def test_recon_never_changes_balances_or_payment_statuses():
    """Reconciliation changes no balances and no payment statuses."""
    uid, _ = create_user_with_token("cust_nobal@example.com")
    _, admin_token = create_user_with_token("admin_nobal@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000094", Decimal("2500.00"))
    ensure_biller("ELEC_RECON", "Electric Utility")

    now = datetime.now(timezone.utc) - timedelta(minutes=10)
    with TestSession() as db:
        p = Payment(
            payment_ref="PAY-NOBAL-01",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("500.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-NOBAL-01",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()
        pay_id = p.id

    # Run recon (which flags MISSING_AT_BILLER)
    resp = client.post("/admin/recon/run", headers={"Authorization": admin_token})
    assert resp.status_code == 200

    # Verify balance and status remain strictly unchanged
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("2500.00")
        pay = db.get(Payment, pay_id)
        assert pay.status == PaymentStatus.SETTLED


# ─────────────────────────────────────────────────────────────
# 6. RESOLVE TWICE RETURNS 409 CONFLICT
# ─────────────────────────────────────────────────────────────
def test_recon_resolve_twice_returns_409():
    """Resolving an already resolved or closed exception returns 409 Conflict."""
    uid, _ = create_user_with_token("cust_res@example.com")
    _, admin_token = create_user_with_token("admin_res@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000095", Decimal("1000.00"))
    ensure_biller("ELEC_RECON", "Electric Utility")

    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    with TestSession() as db:
        p = Payment(
            payment_ref="PAY-RES-01",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("100.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-RES-01",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()

    # Run recon to create exception
    client.post("/admin/recon/run", headers={"Authorization": admin_token})

    # Get exception ID
    list_resp = client.get("/admin/recon/exceptions", headers={"Authorization": admin_token})
    assert list_resp.status_code == 200
    exc_id = list_resp.json()["items"][0]["id"]

    # First resolve: succeeds
    res1 = client.post(
        f"/admin/recon/exceptions/{exc_id}/resolve",
        headers={"Authorization": admin_token},
        json={"resolution_note": "Investigated and verified with biller", "status": "RESOLVED"},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "RESOLVED"

    # Second resolve: returns 409 Conflict
    res2 = client.post(
        f"/admin/recon/exceptions/{exc_id}/resolve",
        headers={"Authorization": admin_token},
        json={"resolution_note": "Attempt duplicate resolve", "status": "RESOLVED"},
    )
    assert res2.status_code == 409


# ─────────────────────────────────────────────────────────────
# 7. ROLE-BASED ACCESS CONTROL
# ─────────────────────────────────────────────────────────────
def test_recon_authorization_customer_forbidden():
    """Customer gets 403 on all recon endpoints; risk analyst has read access."""
    _, cust_token = create_user_with_token("cust_auth@example.com", role=UserRole.CUSTOMER)
    _, analyst_token = create_user_with_token("analyst_auth@example.com", role=UserRole.RISK_ANALYST)
    _, admin_token = create_user_with_token("admin_auth@example.com", role=UserRole.ADMIN)

    # Customer is forbidden across all recon endpoints
    assert client.post("/admin/recon/run", headers={"Authorization": cust_token}).status_code == 403
    assert client.get("/admin/recon/exceptions", headers={"Authorization": cust_token}).status_code == 403
    assert client.get("/admin/recon/exceptions/1", headers={"Authorization": cust_token}).status_code == 403
    assert client.post("/admin/recon/exceptions/1/resolve", headers={"Authorization": cust_token}, json={"resolution_note": "x", "status": "RESOLVED"}).status_code == 403

    # Risk analyst can read exceptions
    assert client.get("/admin/recon/exceptions", headers={"Authorization": analyst_token}).status_code == 200
    # But cannot run recon or resolve exceptions
    assert client.post("/admin/recon/run", headers={"Authorization": analyst_token}).status_code == 403
    assert client.post("/admin/recon/exceptions/1/resolve", headers={"Authorization": analyst_token}, json={"resolution_note": "x", "status": "RESOLVED"}).status_code == 403


# ─────────────────────────────────────────────────────────────
# 8. AUDIT HASH CHAIN VALIDITY
# ─────────────────────────────────────────────────────────────
def test_recon_audit_hash_chain_valid():
    """Reconciliation logs RECON_RUN_COMPLETED and RECON_EXCEPTION_RAISED, and /audit/verify remains valid."""
    uid, _ = create_user_with_token("cust_aud@example.com")
    _, admin_token = create_user_with_token("admin_aud@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000096", Decimal("1000.00"))
    ensure_biller("ELEC_RECON", "Electric Utility")

    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    with TestSession() as db:
        p = Payment(
            payment_ref="PAY-AUD-01",
            user_id=uid,
            sender_account_id=acc_id,
            biller_code="ELEC_RECON",
            amount=Decimal("100.00"),
            status=PaymentStatus.SETTLED,
            rail_reference="RAIL-AUD-01",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()

    # Trigger recon
    client.post("/admin/recon/run", headers={"Authorization": admin_token})

    # Resolve exception
    list_resp = client.get("/admin/recon/exceptions", headers={"Authorization": admin_token})
    exc_id = list_resp.json()["items"][0]["id"]
    client.post(
        f"/admin/recon/exceptions/{exc_id}/resolve",
        headers={"Authorization": admin_token},
        json={"resolution_note": "Resolved and logged", "status": "RESOLVED"},
    )

    with TestSession() as db:
        run_logs = db.scalars(select(AuditLog).where(AuditLog.event_type == "RECON_RUN_COMPLETED")).all()
        assert len(run_logs) >= 1
        exc_logs = db.scalars(select(AuditLog).where(AuditLog.event_type == "RECON_EXCEPTION_RAISED")).all()
        assert len(exc_logs) >= 1
        res_logs = db.scalars(select(AuditLog).where(AuditLog.event_type == "RECON_EXCEPTION_RESOLVED")).all()
        assert len(res_logs) >= 1

    # Cryptographic verification
    v_resp = client.get("/audit/verify", headers={"Authorization": admin_token})
    assert v_resp.status_code == 200
    vdata = v_resp.json()
    assert vdata["valid"] is True
    assert vdata["first_broken_id"] is None
