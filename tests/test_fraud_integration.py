"""
Integration tests for Phase 6: Transaction Limits & Rule-Based Fraud Engine.

Covers:
  - Configurable transaction limits: SINGLE_TRANSFER_LIMIT and 24h DAILY_TRANSFER_LIMIT (HTTP 400)
  - LOW risk transfer completes immediately with no alert
  - HIGH risk transfer is held in PENDING_REVIEW; balances remain untouched; FraudAlert OPEN created
  - Customer response never exposes risk score, risk level, or triggered rules
  - Replaying Idempotency-Key on held transfer returns cached PENDING_REVIEW without duplicate alert
  - Customer role rejected from /fraud/alerts endpoints with HTTP 403 Forbidden
  - Analyst approve moves money atomically and marks transaction COMPLETED
  - Approving a second time returns HTTP 409 Conflict
  - Reject moves no money and marks transaction REJECTED
  - Escalate requires a non-empty note and sets alert status ESCALATED
  - "Hold, don't move": Approving after sender balance drops fails safely (marks FAILED)
  - Separation of duties: Analyst who owns sender or recipient account cannot review (HTTP 403)
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import uuid

import pytest
from conftest import TestSession, client

from app.accounts.models import Account, AccountStatus
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.fraud.models import AlertStatus, FraudAlert, RiskLevel
from app.transactions.models import Transaction, TransactionStatus


def seed_user_and_account(
    email: str,
    full_name: str,
    initial_balance: str = "0.00",
    role: UserRole = UserRole.CUSTOMER,
    password: str = "Password123!",
    age_days: int = 60,
) -> tuple[int, int, str]:
    """Helper to seed user and funded checking account."""
    db = TestSession()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=age_days)

    user = User(
        email=email,
        hashed_password=hash_password(password),
        full_name=full_name,
        role=role,
        is_active=True,
        created_at=created_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    account = Account(
        user_id=user.id,
        account_number=f"{user.id:010d}",
        account_type="checking",
        balance=Decimal(initial_balance),
        status=AccountStatus.ACTIVE,
        created_at=created_at,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    u_id, a_id, a_num = user.id, account.id, account.account_number
    db.close()
    return u_id, a_id, a_num


def get_auth_headers(email: str, password: str = "Password123!") -> dict[str, str]:
    """Log in and return Authorization header dict."""
    res = client.post("/auth/login", data={"username": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ── TEST CASES ─────────────────────────────────────────────────────────────

def test_transfer_limits_enforced() -> None:
    """Single transfer limit and 24h daily transfer limit are enforced before fraud scoring."""
    # Seed sender with $20,000 balance
    _, _, sender_num = seed_user_and_account("limit_sender@example.com", "Limit Sender", "20000.00")
    _, _, recip_num = seed_user_and_account("limit_recip@example.com", "Limit Recipient", "100.00")
    headers = get_auth_headers("limit_sender@example.com")

    # 1. Single transfer limit check (default 5000.00, send 5000.01)
    res_single = client.post(
        "/transactions",
        json={"recipient_account_number": recip_num, "amount": "5000.01"},
        headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert res_single.status_code == 400
    assert "exceeds single transfer limit" in res_single.json()["detail"]

    # 2. Daily transfer limit check (default 10,000.00)
    # First valid transfer: 4000.00
    res_t1 = client.post(
        "/transactions",
        json={"recipient_account_number": recip_num, "amount": "1000.00"},
        headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
    )
    # Note: 1000 to new recipient might trigger MEDIUM, but completes normally
    assert res_t1.status_code == 201
    assert res_t1.json()["status"] == "completed"

    # Pre-seed a completed transaction in DB to simulate recent 24h usage
    db = TestSession()
    sender_acc = db.query(Account).filter_by(account_number=sender_num).first()
    recip_acc = db.query(Account).filter_by(account_number=recip_num).first()
    tx_prior = Transaction(
        transaction_ref=f"TX-{uuid.uuid4().hex[:12].upper()}",
        sender_account_id=sender_acc.id,
        recipient_account_id=recip_acc.id,
        amount=Decimal("8500.00"),
        status=TransactionStatus.COMPLETED,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        completed_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(tx_prior)
    db.commit()
    db.close()

    # Total completed today is now 1000 + 8500 = 9500.
    # Attempting to send 1000 more would push total to 10500 (> 10000 daily limit)
    res_daily = client.post(
        "/transactions",
        json={"recipient_account_number": recip_num, "amount": "1000.00"},
        headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert res_daily.status_code == 400
    assert "daily transfer limit" in res_daily.json()["detail"]


def test_low_risk_transfer_completes_normally() -> None:
    """Established account sending small amount to established recipient triggers 0 points (LOW)."""
    _, s_id, s_num = seed_user_and_account("low_sender@example.com", "Low Sender", "1000.00", age_days=60)
    _, r_id, r_num = seed_user_and_account("low_recip@example.com", "Low Recip", "500.00", age_days=60)
    headers = get_auth_headers("low_sender@example.com")

    # Seed a prior completed transaction between them so NEW_RECIPIENT does not trigger
    db = TestSession()
    prior = Transaction(
        transaction_ref="TX-LOWPRIOR01",
        sender_account_id=s_id,
        recipient_account_id=r_id,
        amount=Decimal("10.00"),
        status=TransactionStatus.COMPLETED,
        created_at=datetime.now(timezone.utc) - timedelta(days=5),
        completed_at=datetime.now(timezone.utc) - timedelta(days=5),
    )
    db.add(prior)
    db.commit()
    db.close()

    # Small transfer of $50.00 -> 0 points (LOW)
    res = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "50.00"},
        headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "completed"

    # Verify no fraud alert was created
    db = TestSession()
    alert = db.query(FraudAlert).filter_by(transaction_id=data["id"]).first()
    assert alert is None
    db.close()


def test_high_risk_transfer_held_and_balances_unchanged() -> None:
    """
    HIGH risk transfer is held in status PENDING_REVIEW;
    Balances are completely unchanged;
    FraudAlert is created with status OPEN;
    Customer response never contains risk data.
    """
    _, s_id, s_num = seed_user_and_account("high_sender@example.com", "High Sender", "5000.00", age_days=60)
    _, r_id, r_num = seed_user_and_account("high_recip@example.com", "High Recip", "200.00", age_days=60)
    headers = get_auth_headers("high_sender@example.com")

    # Transfer $2,500.00 to a brand-new recipient:
    # - LARGE_AMOUNT (amount >= 2000): 40 pts
    # - NEW_RECIPIENT_LARGE (first transfer and amount >= 500): 30 pts
    # Total = 70 pts -> HIGH (>= 60)
    idem_key = str(uuid.uuid4())
    res = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "2500.00", "description": "Big gift"},
        headers={**headers, "Idempotency-Key": idem_key},
    )
    assert res.status_code == 201
    data = res.json()

    # 1. Transaction held in PENDING_REVIEW
    assert data["status"] == "pending_review"
    assert data["completed_at"] is None
    assert "held" in data["message"].lower()

    # 2. Customer response NEVER exposes risk data
    assert "risk_score" not in data
    assert "risk_level" not in data
    assert "triggered_rules" not in data

    # 3. HOLD, DON'T MOVE: Balances remain unchanged!
    db = TestSession()
    sender_acc = db.get(Account, s_id)
    recip_acc = db.get(Account, r_id)
    assert sender_acc.balance == Decimal("5000.00")
    assert recip_acc.balance == Decimal("200.00")

    # 4. Fraud alert created with status OPEN and full explainability
    alert = db.query(FraudAlert).filter_by(transaction_id=data["id"]).first()
    assert alert is not None
    assert alert.status == AlertStatus.OPEN
    assert alert.risk_level == RiskLevel.HIGH
    assert alert.risk_score == 70
    rule_names = [r["rule"] for r in alert.triggered_rules]
    assert "LARGE_AMOUNT" in rule_names
    assert "NEW_RECIPIENT_LARGE" in rule_names
    db.close()

    # 5. Idempotency replay returns exact same PENDING_REVIEW without creating second alert
    res_replay = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "2500.00", "description": "Big gift"},
        headers={**headers, "Idempotency-Key": idem_key},
    )
    assert res_replay.status_code == 201
    assert res_replay.json()["id"] == data["id"]
    assert res_replay.json()["status"] == "pending_review"

    db = TestSession()
    alerts_count = db.query(FraudAlert).filter_by(transaction_id=data["id"]).count()
    assert alerts_count == 1
    db.close()


def test_customer_cannot_access_fraud_endpoints() -> None:
    """Customer role is strictly forbidden (HTTP 403) from accessing /fraud endpoints."""
    seed_user_and_account("cust_test@example.com", "Cust Test", "100.00")
    headers = get_auth_headers("cust_test@example.com")

    # GET /fraud/alerts
    res_list = client.get("/fraud/alerts", headers=headers)
    assert res_list.status_code == 403

    # GET /fraud/alerts/1
    res_detail = client.get("/fraud/alerts/1", headers=headers)
    assert res_detail.status_code == 403

    # POST /fraud/alerts/1/approve
    res_app = client.post("/fraud/alerts/1/approve", json={"note": "ok"}, headers=headers)
    assert res_app.status_code == 403

    # POST /fraud/alerts/1/reject
    res_rej = client.post("/fraud/alerts/1/reject", json={"note": "no"}, headers=headers)
    assert res_rej.status_code == 403

    # POST /fraud/alerts/1/escalate
    res_esc = client.post("/fraud/alerts/1/escalate", json={"note": "help"}, headers=headers)
    assert res_esc.status_code == 403


def test_analyst_approve_moves_money_exactly_once() -> None:
    """Analyst approves held alert; transfer executes; double-approve returns 409."""
    # Seed users and analyst
    _, s_id, s_num = seed_user_and_account("appr_sender@example.com", "Appr Sender", "5000.00", age_days=60)
    _, r_id, r_num = seed_user_and_account("appr_recip@example.com", "Appr Recip", "100.00", age_days=60)
    seed_user_and_account("analyst_appr@example.com", "Analyst Appr", role=UserRole.RISK_ANALYST)

    headers_sender = get_auth_headers("appr_sender@example.com")
    headers_analyst = get_auth_headers("analyst_appr@example.com")

    # High risk transfer of 3000 (held)
    res_tx = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "3000.00"},
        headers={**headers_sender, "Idempotency-Key": str(uuid.uuid4())},
    )
    tx_id = res_tx.json()["id"]

    db = TestSession()
    alert = db.query(FraudAlert).filter_by(transaction_id=tx_id).first()
    alert_id = alert.id
    db.close()

    # Analyst fetches alert details
    res_alert = client.get(f"/fraud/alerts/{alert_id}", headers=headers_analyst)
    assert res_alert.status_code == 200
    alert_data = res_alert.json()
    assert alert_data["risk_level"] == "high"
    assert alert_data["status"] == "open"
    assert len(alert_data["triggered_rules"]) >= 1
    assert alert_data["transaction"]["id"] == tx_id

    # Analyst approves transfer
    res_appr = client.post(
        f"/fraud/alerts/{alert_id}/approve",
        json={"note": "Customer verified via phone call"},
        headers=headers_analyst,
    )
    assert res_appr.status_code == 200
    appr_data = res_appr.json()
    assert appr_data["status"] == "resolved"
    assert appr_data["decision_note"] == "Customer verified via phone call"

    # Verify money moved in database
    db = TestSession()
    sender_acc = db.get(Account, s_id)
    recip_acc = db.get(Account, r_id)
    tx = db.get(Transaction, tx_id)
    assert sender_acc.balance == Decimal("2000.00")
    assert recip_acc.balance == Decimal("3100.00")
    assert tx.status == TransactionStatus.COMPLETED
    assert tx.completed_at is not None
    db.close()

    # DOUBLE-APPROVE returns 409 Conflict
    res_double = client.post(
        f"/fraud/alerts/{alert_id}/approve",
        json={"note": "Trying again"},
        headers=headers_analyst,
    )
    assert res_double.status_code == 409
    assert "already been decided" in res_double.json()["detail"]

    # Money did not move twice
    db = TestSession()
    assert db.get(Account, s_id).balance == Decimal("2000.00")
    db.close()


def test_analyst_reject_moves_no_money() -> None:
    """Analyst rejects alert; transaction becomes REJECTED; no money moves."""
    _, s_id, s_num = seed_user_and_account("rej_sender@example.com", "Rej Sender", "5000.00", age_days=60)
    _, r_id, r_num = seed_user_and_account("rej_recip@example.com", "Rej Recip", "100.00", age_days=60)
    seed_user_and_account("analyst_rej@example.com", "Analyst Rej", role=UserRole.RISK_ANALYST)

    headers_sender = get_auth_headers("rej_sender@example.com")
    headers_analyst = get_auth_headers("analyst_rej@example.com")

    # Hold transfer
    res_tx = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "3000.00"},
        headers={**headers_sender, "Idempotency-Key": str(uuid.uuid4())},
    )
    tx_id = res_tx.json()["id"]

    db = TestSession()
    alert = db.query(FraudAlert).filter_by(transaction_id=tx_id).first()
    alert_id = alert.id
    db.close()

    # Reject
    res_rej = client.post(
        f"/fraud/alerts/{alert_id}/reject",
        json={"note": "Confirmed stolen credentials"},
        headers=headers_analyst,
    )
    assert res_rej.status_code == 200
    assert res_rej.json()["status"] == "resolved"

    # Verify transaction status and balances
    db = TestSession()
    tx = db.get(Transaction, tx_id)
    assert tx.status == TransactionStatus.REJECTED
    assert db.get(Account, s_id).balance == Decimal("5000.00")
    assert db.get(Account, r_id).balance == Decimal("100.00")
    db.close()


def test_analyst_escalate_requires_note() -> None:
    """Escalating requires an explanatory note; sets status to ESCALATED."""
    _, _, s_num = seed_user_and_account("esc_sender@example.com", "Esc Sender", "5000.00", age_days=60)
    _, _, r_num = seed_user_and_account("esc_recip@example.com", "Esc Recip", "100.00", age_days=60)
    seed_user_and_account("analyst_esc@example.com", "Analyst Esc", role=UserRole.RISK_ANALYST)

    headers_sender = get_auth_headers("esc_sender@example.com")
    headers_analyst = get_auth_headers("analyst_esc@example.com")

    res_tx = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "3000.00"},
        headers={**headers_sender, "Idempotency-Key": str(uuid.uuid4())},
    )
    tx_id = res_tx.json()["id"]

    db = TestSession()
    alert_id = db.query(FraudAlert).filter_by(transaction_id=tx_id).first().id
    db.close()

    # Empty note fails with 422 or 400
    res_empty = client.post(f"/fraud/alerts/{alert_id}/escalate", json={"note": ""}, headers=headers_analyst)
    assert res_empty.status_code in [400, 422]

    # Valid note escalates
    res_esc = client.post(
        f"/fraud/alerts/{alert_id}/escalate",
        json={"note": "Escalating to Senior Risk Lead for high-value AML check"},
        headers=headers_analyst,
    )
    assert res_esc.status_code == 200
    assert res_esc.json()["status"] == "escalated"


def test_approve_after_sender_balance_dropped_fails_safely() -> None:
    """
    'Hold, don't move' principle:
    Sender has $5,000 when initiating $4,600 held transfer.
    Before review, sender spends $2,000 (balance drops to $3,000).
    On approval, system re-checks balance under row locks:
    Transfer cannot execute -> transaction is marked FAILED safely.
    """
    _, s_id, s_num = seed_user_and_account("drop_sender@example.com", "Drop Sender", "5000.00", age_days=60)
    _, r_id, r_num = seed_user_and_account("drop_recip@example.com", "Drop Recip", "100.00", age_days=60)
    seed_user_and_account("analyst_drop@example.com", "Analyst Drop", role=UserRole.RISK_ANALYST)

    headers_sender = get_auth_headers("drop_sender@example.com")
    headers_analyst = get_auth_headers("analyst_drop@example.com")

    # Held transfer of $4,600.00
    res_tx = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "4600.00"},
        headers={**headers_sender, "Idempotency-Key": str(uuid.uuid4())},
    )
    tx_id = res_tx.json()["id"]

    db = TestSession()
    alert_id = db.query(FraudAlert).filter_by(transaction_id=tx_id).first().id

    # Now sender balance drops directly in DB (simulating another transfer or withdrawal)
    sender = db.get(Account, s_id)
    sender.balance = Decimal("2000.00")
    db.commit()
    db.close()

    # Analyst attempts to approve
    res_appr = client.post(
        f"/fraud/alerts/{alert_id}/approve",
        json={"note": "Approved by analyst"},
        headers=headers_analyst,
    )
    assert res_appr.status_code == 200
    alert_res = res_appr.json()
    assert alert_res["status"] == "resolved"
    assert "Insufficient funds" in alert_res["decision_note"]

    # Transaction is marked FAILED; recipient received nothing; sender balance intact at 2000
    db = TestSession()
    tx = db.get(Transaction, tx_id)
    assert tx.status == TransactionStatus.FAILED
    assert db.get(Account, s_id).balance == Decimal("2000.00")
    assert db.get(Account, r_id).balance == Decimal("100.00")
    db.close()


def test_analyst_cannot_review_own_transaction() -> None:
    """Separation of duties: An analyst/admin who owns the sender or recipient account cannot review (403)."""
    # Seed analyst who also has an account
    analyst_u_id, _, s_num = seed_user_and_account(
        "conflict_analyst@example.com",
        "Conflict Analyst",
        initial_balance="5000.00",
        role=UserRole.RISK_ANALYST,
        age_days=60,
    )
    _, _, r_num = seed_user_and_account("party_b@example.com", "Party B", "100.00", age_days=60)

    headers_analyst = get_auth_headers("conflict_analyst@example.com")

    # Analyst sends large transfer that gets held
    res_tx = client.post(
        "/transactions",
        json={"recipient_account_number": r_num, "amount": "3000.00"},
        headers={**headers_analyst, "Idempotency-Key": str(uuid.uuid4())},
    )
    tx_id = res_tx.json()["id"]

    db = TestSession()
    alert_id = db.query(FraudAlert).filter_by(transaction_id=tx_id).first().id
    db.close()

    # Same analyst tries to approve their own transfer -> 403 Forbidden!
    res_appr = client.post(f"/fraud/alerts/{alert_id}/approve", headers=headers_analyst)
    assert res_appr.status_code == 403
    assert "Separation of duties" in res_appr.json()["detail"]

    # Same analyst tries to reject their own transfer -> 403 Forbidden!
    res_rej = client.post(f"/fraud/alerts/{alert_id}/reject", headers=headers_analyst)
    assert res_rej.status_code == 403
    assert "Separation of duties" in res_rej.json()["detail"]

    # Same analyst tries to escalate their own transfer -> 403 Forbidden!
    res_esc = client.post(
        f"/fraud/alerts/{alert_id}/escalate",
        json={"note": "Escalating myself"},
        headers=headers_analyst,
    )
    assert res_esc.status_code == 403
    assert "Separation of duties" in res_esc.json()["detail"]
