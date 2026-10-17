"""
SentinelPay – Test Suite for Phase 9 (Part B: Disputes & SLA).

Tests cover:
  1. Customer files dispute; case_ref and SLA deadline are set.
  2. Customer cannot dispute someone else's payment (403 Forbidden).
  3. Second active dispute on the same payment returns 409 Conflict.
  4. Idempotent replay of POST /disputes creates only one dispute and returns cached response.
  5. Refund credits exactly once; second resolve-refund returns 409; concurrent calls produce exactly one refund.
  6. Refund refused when payment is already REVERSED (409 Conflict).
  7. Overdue dispute is escalated by escalation sweep; running sweep twice does not double-escalate.
  8. Customer timeline never shows internal staff notes (visible_to_customer=False).
  9. Staff member cannot work their own dispute (Separation of duties -> 403 Forbidden).
 10. Illegal state moves are rejected by state machine.
 11. Auto-link to an open reconciliation exception works.
 12. Every state change has a DisputeEvent and an audit row, and /audit/verify is still valid.
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
from app.disputes.models import (
    Dispute,
    DisputeCategory,
    DisputeEvent,
    DisputeRefund,
    DisputeStatus,
)
from app.disputes.service import resolve_dispute_refund, sweep_escalate_overdue_disputes
from app.disputes.state_machine import IllegalDisputeTransition, transition_dispute
from app.payments.models import Payment, PaymentStatus
from app.recon.models import (
    ExceptionStatus,
    ExceptionType,
    ReconciliationException,
    ReconciliationRun,
)
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
            full_name="Dispute Tester",
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


import secrets


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


def create_payment(user_id: int, account_id: int, amount: Decimal, status: PaymentStatus = PaymentStatus.SETTLED) -> int:
    """Helper: create a payment record."""
    with TestSession() as db:
        now = datetime.now(timezone.utc)
        rand = secrets.token_hex(6).upper()
        p = Payment(
            payment_ref=f"PAY-{rand}",
            user_id=user_id,
            sender_account_id=account_id,
            biller_code="ELEC_DSP",
            amount=amount,
            status=status,
            rail_reference=f"RAIL-{rand}",
            created_at=now,
            updated_at=now,
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        return p.id


# ─────────────────────────────────────────────────────────────
# 1. CUSTOMER FILES DISPUTE (CASE REF & SLA SET)
# ─────────────────────────────────────────────────────────────
def test_01_customer_files_dispute_case_ref_and_sla_set():
    """Customer files a dispute; case ref and SLA are set properly."""
    uid, token = create_user_with_token("cust_dsp1@example.com")
    acc_id = create_account(uid, "1000000081", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-01"},
        json={
            "payment_id": pay_id,
            "category": "DUPLICATE_DEBIT",
            "description": "I was charged twice for the same electricity bill.",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["case_ref"].startswith("DSP-")
    assert data["status"] == "OPEN"
    assert data["category"] == "DUPLICATE_DEBIT"
    assert "sla_due_at" in data
    assert len(data["timeline"]) >= 1


# ─────────────────────────────────────────────────────────────
# 2. CUSTOMER CANNOT DISPUTE SOMEONE ELSE'S PAYMENT (403)
# ─────────────────────────────────────────────────────────────
def test_02_customer_cannot_dispute_someone_elses_payment():
    """Customer cannot dispute someone else's payment (403)."""
    uid_a, token_a = create_user_with_token("cust_a_dsp@example.com")
    uid_b, token_b = create_user_with_token("cust_b_dsp@example.com")
    acc_id_a = create_account(uid_a, "1000000082", Decimal("1000.00"))
    pay_id_a = create_payment(uid_a, acc_id_a, Decimal("100.00"))

    # Customer B tries to dispute Customer A's payment
    resp = client.post(
        "/disputes",
        headers={"Authorization": token_b, "Idempotency-Key": "DSP-IDEMP-02"},
        json={
            "payment_id": pay_id_a,
            "category": "UNAUTHORIZED",
            "description": "Unauthorized transaction on someone else's account.",
        },
    )
    assert resp.status_code == 403


# ─────────────────────────────────────────────────────────────
# 3. SECOND ACTIVE DISPUTE ON SAME PAYMENT RETURNS 409
# ─────────────────────────────────────────────────────────────
def test_03_second_active_dispute_returns_409():
    """Second active dispute on the same payment returns 409."""
    uid, token = create_user_with_token("cust_dsp3@example.com")
    acc_id = create_account(uid, "1000000083", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    resp1 = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-03-A"},
        json={
            "payment_id": pay_id,
            "category": "DUPLICATE_DEBIT",
            "description": "First dispute.",
        },
    )
    assert resp1.status_code == 201

    # Second dispute on same payment with a different idempotency key
    resp2 = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-03-B"},
        json={
            "payment_id": pay_id,
            "category": "DUPLICATE_DEBIT",
            "description": "Second dispute attempt.",
        },
    )
    assert resp2.status_code == 409


# ─────────────────────────────────────────────────────────────
# 4. IDEMPOTENT REPLAY OF POST /disputes CREATES ONE DISPUTE
# ─────────────────────────────────────────────────────────────
def test_04_idempotent_replay_creates_one_dispute():
    """Idempotent replay of POST /disputes returns cached response and creates one dispute."""
    uid, token = create_user_with_token("cust_dsp4@example.com")
    acc_id = create_account(uid, "1000000084", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    idemp_key = "DSP-IDEMP-REPLAY-04"
    payload = {
        "payment_id": pay_id,
        "category": "PAID_BUT_NOT_CREDITED",
        "description": "Money deducted but bill unpaid at utility provider.",
    }

    resp1 = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": idemp_key},
        json=payload,
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": idemp_key},
        json=payload,
    )
    assert resp2.status_code == 201
    assert resp2.json()["id"] == resp1.json()["id"]

    with TestSession() as db:
        disputes = db.scalars(select(Dispute).where(Dispute.payment_id == pay_id)).all()
        assert len(disputes) == 1


# ─────────────────────────────────────────────────────────────
# 5. REFUND CREDITS ONCE, 409 ON SECOND, CONCURRENCY SAFE
# ─────────────────────────────────────────────────────────────
def test_05_resolve_refund_credits_once_and_concurrency_safe():
    """Refund credits exactly once; a second resolve-refund returns 409; concurrent calls produce exactly one refund."""
    uid, token = create_user_with_token("cust_dsp5@example.com")
    _, analyst_token = create_user_with_token("analyst_dsp5@example.com", role=UserRole.RISK_ANALYST)
    acc_id = create_account(uid, "1000000085", Decimal("800.00"))
    pay_id = create_payment(uid, acc_id, Decimal("200.00"), status=PaymentStatus.SETTLED)

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-05"},
        json={
            "payment_id": pay_id,
            "category": "DUPLICATE_DEBIT",
            "description": "Double debit dispute.",
        },
    )
    assert resp.status_code == 201
    dsp_id = resp.json()["id"]

    # First refund resolution succeeds
    res1 = client.post(
        f"/staff/disputes/{dsp_id}/resolve-refund",
        headers={"Authorization": analyst_token},
        json={"note": "Verified duplicate debit. Refunding customer."},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "RESOLVED_REFUNDED"

    # Balance credited (800 + 200 = 1000)
    with TestSession() as db:
        acc = db.get(Account, acc_id)
        assert acc.balance == Decimal("1000.00")
        refunds = db.scalars(select(DisputeRefund).where(DisputeRefund.dispute_id == dsp_id)).all()
        assert len(refunds) == 1

    # Second refund resolution returns 409 Conflict
    res2 = client.post(
        f"/staff/disputes/{dsp_id}/resolve-refund",
        headers={"Authorization": analyst_token},
        json={"note": "Attempt second refund."},
    )
    assert res2.status_code == 409

    # Concurrent refund execution safety
    dsp2_resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-05-B"},
        json={
            "payment_id": create_payment(uid, acc_id, Decimal("50.00"), status=PaymentStatus.SETTLED),
            "category": "OTHER",
            "description": "Concurrency refund test.",
        },
    )
    dsp2_id = dsp2_resp.json()["id"]

    def run_concurrent_refund():
        with TestSession() as db:
            staff_user = db.scalar(select(User).where(User.email == "analyst_dsp5@example.com"))
            try:
                resolve_dispute_refund(db, dsp2_id, staff_user, "Concurrent resolution")
                return True
            except Exception:
                db.rollback()
                return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_concurrent_refund)
        f2 = executor.submit(run_concurrent_refund)
        r1 = f1.result()
        r2 = f2.result()

    # Exactly one succeeded and one failed
    assert (r1 and not r2) or (r2 and not r1)
    with TestSession() as db:
        refund_count = len(db.scalars(select(DisputeRefund).where(DisputeRefund.dispute_id == dsp2_id)).all())
        assert refund_count == 1


# ─────────────────────────────────────────────────────────────
# 6. REFUND REFUSED WHEN PAYMENT WAS ALREADY REVERSED
# ─────────────────────────────────────────────────────────────
def test_06_refund_refused_when_payment_already_reversed():
    """Refund refused when the payment was already REVERSED (customer already refunded)."""
    uid, token = create_user_with_token("cust_dsp6@example.com")
    _, analyst_token = create_user_with_token("analyst_dsp6@example.com", role=UserRole.RISK_ANALYST)
    acc_id = create_account(uid, "1000000086", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"), status=PaymentStatus.REVERSED)

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-06"},
        json={
            "payment_id": pay_id,
            "category": "PAID_BUT_NOT_CREDITED",
            "description": "Claiming refund for reversed payment.",
        },
    )
    assert resp.status_code == 201
    dsp_id = resp.json()["id"]

    # Attempt to resolve-refund
    res = client.post(
        f"/staff/disputes/{dsp_id}/resolve-refund",
        headers={"Authorization": analyst_token},
        json={"note": "Attempt refunding an already reversed payment."},
    )
    assert res.status_code == 409


# ─────────────────────────────────────────────────────────────
# 7. OVERDUE DISPUTE ESCALATED BY SWEEP (NO DOUBLE ESCALATION)
# ─────────────────────────────────────────────────────────────
def test_07_overdue_dispute_escalated_by_sweep():
    """Overdue dispute is escalated by the sweep; running the sweep twice does not double-escalate."""
    uid, token = create_user_with_token("cust_dsp7@example.com")
    _, admin_token = create_user_with_token("admin_dsp7@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000087", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-07"},
        json={
            "payment_id": pay_id,
            "category": "UNAUTHORIZED",
            "description": "Overdue SLA dispute.",
        },
    )
    dsp_id = resp.json()["id"]

    # Fast-forward SLA due date to the past
    with TestSession() as db:
        d = db.get(Dispute, dsp_id)
        d.sla_due_at = datetime.now(timezone.utc) - timedelta(hours=2)
        db.commit()

    # First escalation sweep: finds 1, escalates 1
    sw1 = client.post("/admin/disputes/escalation-sweep", headers={"Authorization": admin_token})
    assert sw1.status_code == 200
    assert sw1.json()["escalated"] == 1

    with TestSession() as db:
        d = db.get(Dispute, dsp_id)
        assert d.status == DisputeStatus.ESCALATED
        assert d.escalation_level == 1
        assert d.escalated_at is not None

    # Second escalation sweep: dispute is already in ESCALATED status, so it does not escalate again
    sw2 = client.post("/admin/disputes/escalation-sweep", headers={"Authorization": admin_token})
    assert sw2.status_code == 200
    assert sw2.json()["escalated"] == 0


# ─────────────────────────────────────────────────────────────
# 8. CUSTOMER TIMELINE NEVER SHOWS INTERNAL NOTES
# ─────────────────────────────────────────────────────────────
def test_08_customer_timeline_never_shows_internal_notes():
    """Customer timeline never shows internal notes (visible_to_customer=False)."""
    uid, token = create_user_with_token("cust_dsp8@example.com")
    _, analyst_token = create_user_with_token("analyst_dsp8@example.com", role=UserRole.RISK_ANALYST)
    acc_id = create_account(uid, "1000000088", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-08"},
        json={
            "payment_id": pay_id,
            "category": "OTHER",
            "description": "Checking timeline privacy.",
        },
    )
    dsp_id = resp.json()["id"]

    # Staff adds an internal status update with visible_to_customer=False
    client.post(
        f"/staff/disputes/{dsp_id}/status",
        headers={"Authorization": analyst_token},
        json={
            "status": "INVESTIGATING",
            "note": "SECRET INTERNAL NOTE: Suspected customer fraud collusion.",
            "visible_to_customer": False,
        },
    )

    # Customer fetches their dispute
    cust_view = client.get(f"/disputes/{dsp_id}", headers={"Authorization": token})
    assert cust_view.status_code == 200
    customer_notes = [e["note"] for e in cust_view.json()["timeline"]]
    for n in customer_notes:
        assert "SECRET INTERNAL NOTE" not in (n or "")

    # Staff fetches the dispute: can see the internal note
    staff_view = client.get(f"/staff/disputes/{dsp_id}", headers={"Authorization": analyst_token})
    assert staff_view.status_code == 200
    staff_notes = [e["note"] for e in staff_view.json()["timeline"]]
    assert any("SECRET INTERNAL NOTE" in (n or "") for n in staff_notes)


# ─────────────────────────────────────────────────────────────
# 9. SEPARATION OF DUTIES (STAFF CANNOT WORK THEIR OWN DISPUTE)
# ─────────────────────────────────────────────────────────────
def test_09_staff_cannot_work_their_own_dispute():
    """Staff cannot work their own dispute (Separation of duties -> 403 Forbidden)."""
    # Create a user with RISK_ANALYST role
    uid, analyst_token = create_user_with_token("dual_role_staff@example.com", role=UserRole.RISK_ANALYST)
    acc_id = create_account(uid, "1000000089", Decimal("500.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    # The analyst files a dispute as a customer
    resp = client.post(
        "/disputes",
        headers={"Authorization": analyst_token, "Idempotency-Key": "DSP-IDEMP-09"},
        json={
            "payment_id": pay_id,
            "category": "DUPLICATE_DEBIT",
            "description": "My own personal dispute.",
        },
    )
    dsp_id = resp.json()["id"]

    # Now the analyst tries to assign, update, or refund their own dispute -> 403
    assert client.post(f"/staff/disputes/{dsp_id}/assign", headers={"Authorization": analyst_token}, json={}).status_code == 403
    assert client.post(f"/staff/disputes/{dsp_id}/status", headers={"Authorization": analyst_token}, json={"status": "INVESTIGATING", "note": "Trying to work my own dispute"}).status_code == 403
    assert client.post(f"/staff/disputes/{dsp_id}/resolve-refund", headers={"Authorization": analyst_token}, json={"note": "Approving my own refund"}).status_code == 403


# ─────────────────────────────────────────────────────────────
# 10. ILLEGAL STATE MOVES ARE REJECTED
# ─────────────────────────────────────────────────────────────
def test_10_illegal_state_moves_rejected():
    """Illegal state moves are rejected."""
    uid, token = create_user_with_token("cust_dsp10@example.com")
    _, analyst_token = create_user_with_token("analyst_dsp10@example.com", role=UserRole.RISK_ANALYST)
    acc_id = create_account(uid, "1000000090", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-10"},
        json={"payment_id": pay_id, "category": "OTHER", "description": "State machine test."},
    )
    dsp_id = resp.json()["id"]

    # Resolve rejected
    client.post(
        f"/staff/disputes/{dsp_id}/resolve-reject",
        headers={"Authorization": analyst_token},
        json={"note": "Rejected."},
    )

    # Try moving from terminal RESOLVED_REJECTED back to OPEN or INVESTIGATING
    res = client.post(
        f"/staff/disputes/{dsp_id}/status",
        headers={"Authorization": analyst_token},
        json={"status": "OPEN", "note": "Reopen"},
    )
    assert res.status_code == 400


# ─────────────────────────────────────────────────────────────
# 11. AUTO-LINK TO OPEN RECONCILIATION EXCEPTION
# ─────────────────────────────────────────────────────────────
def test_11_auto_link_to_open_recon_exception():
    """Auto-link to an open reconciliation exception works."""
    uid, token = create_user_with_token("cust_dsp11@example.com")
    acc_id = create_account(uid, "1000000091", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    # Create an open reconciliation exception for this payment
    with TestSession() as db:
        now = datetime.now(timezone.utc)
        run = ReconciliationRun(started_at=now, started_by=uid)
        db.add(run)
        db.flush()

        exc = ReconciliationException(
            run_id=run.id,
            exception_type=ExceptionType.MISSING_AT_BILLER,
            payment_id=pay_id,
            rail_reference="RAIL-TEST-LINK",
            status=ExceptionStatus.OPEN,
            created_at=now,
        )
        db.add(exc)
        db.commit()
        exc_id = exc.id

    # Customer files dispute on this payment
    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-11"},
        json={
            "payment_id": pay_id,
            "category": "PAID_BUT_NOT_CREDITED",
            "description": "Bill not credited.",
        },
    )
    assert resp.status_code == 201
    dsp_id = resp.json()["id"]

    with TestSession() as db:
        d = db.get(Dispute, dsp_id)
        assert d.linked_exception_id == exc_id


# ─────────────────────────────────────────────────────────────
# 12. AUDIT HASH CHAIN VALIDITY ACROSS ALL DISPUTE ACTIONS
# ─────────────────────────────────────────────────────────────
def test_12_dispute_audit_hash_chain_valid():
    """Every change has a DisputeEvent and an audit row, and /audit/verify is still valid."""
    uid, token = create_user_with_token("cust_dsp12@example.com")
    _, admin_token = create_user_with_token("admin_dsp12@example.com", role=UserRole.ADMIN)
    acc_id = create_account(uid, "1000000092", Decimal("1000.00"))
    pay_id = create_payment(uid, acc_id, Decimal("100.00"))

    # 1. File
    resp = client.post(
        "/disputes",
        headers={"Authorization": token, "Idempotency-Key": "DSP-IDEMP-12"},
        json={"payment_id": pay_id, "category": "OTHER", "description": "Audit check."},
    )
    dsp_id = resp.json()["id"]

    # 2. Assign
    client.post(
        f"/staff/disputes/{dsp_id}/assign",
        headers={"Authorization": admin_token},
        json={},
    )

    # 3. Status update
    client.post(
        f"/staff/disputes/{dsp_id}/status",
        headers={"Authorization": admin_token},
        json={"status": "INVESTIGATING", "note": "Investigating with bank."},
    )

    # 4. Resolve refund
    client.post(
        f"/staff/disputes/{dsp_id}/resolve-refund",
        headers={"Authorization": admin_token},
        json={"note": "Approved refund."},
    )

    # Verify audit events exist
    with TestSession() as db:
        events = list(db.scalars(select(AuditLog).where(AuditLog.entity_type == "dispute")).all())
        event_types = {e.event_type for e in events}
        assert "DISPUTE_FILED" in event_types
        assert "DISPUTE_ASSIGNED" in event_types
        assert "DISPUTE_STATUS_UPDATED" in event_types
        assert "DISPUTE_REFUNDED" in event_types

    # Verify cryptographic hash chain integrity
    v_resp = client.get("/audit/verify", headers={"Authorization": admin_token})
    assert v_resp.status_code == 200
    vdata = v_resp.json()
    assert vdata["valid"] is True
    assert vdata["first_broken_id"] is None
