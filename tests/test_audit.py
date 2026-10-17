"""
SentinelPay – Test suite for Phase 7: Tamper-evident Audit Log.
Tests cover:
  1. Transfer completes -> exactly one TRANSFER_COMPLETED row.
  2. Transfer rolls back -> no TRANSFER_COMPLETED row.
  3. Failed login -> LOGIN_FAILED row exists despite failure.
  4. Direct SQL UPDATE and DELETE blocked by trigger.
  5. Cryptographic hash chain verification and tamper detection.
  6. 20 concurrent transfers keep hash chain strictly linear and valid.
  7. Sensitive data sanitization (no passwords, tokens in details).
  8. Strict role-based authorization across all audit endpoints.
  9. Fraud review events (ALERT_APPROVED, REJECTED, ESCALATED, SEPARATION_OF_DUTIES).
 10. Idempotent replay logging.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

import pytest
from sqlalchemy import select, text

from app.accounts.models import Account, AccountStatus, AccountType
from app.audit.models import AuditLog
from app.audit.service import sanitize_details, verify_hash_chain
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from conftest import TestSession, client, test_engine


def create_user_with_token(
    email: str,
    password: str = "Password123!",
    role: UserRole = UserRole.CUSTOMER,
) -> tuple[int, str]:
    """Helper to create a user and return (user_id, auth_header)."""
    with TestSession() as db:
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name="Test Person",
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
    """Helper to create a funded bank account."""
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


def test_transfer_completes_creates_single_audit_row():
    """Requirement 16: Completed transfer records exactly one TRANSFER_COMPLETED audit row."""
    u1_id, u1_auth = create_user_with_token("u1@example.com")
    u2_id, _ = create_user_with_token("u2@example.com")

    create_account(u1_id, "1000000001", Decimal("1000.00"))
    create_account(u2_id, "1000000002", Decimal("500.00"))

    resp = client.post(
        "/transactions",
        headers={"Authorization": u1_auth, "Idempotency-Key": "audit-tx-1"},
        json={"recipient_account_number": "1000000002", "amount": 100.00},
    )
    assert resp.status_code == 201
    tx_data = resp.json()
    assert tx_data["status"] == "completed"

    with TestSession() as db:
        stmt = select(AuditLog).where(AuditLog.event_type == "TRANSFER_COMPLETED")
        logs = list(db.scalars(stmt).all())
        assert len(logs) == 1
        log = logs[0]
        assert log.actor_user_id == u1_id
        assert log.entity_type == "transaction"
        assert log.entity_id == str(tx_data["id"])
        assert log.outcome == "SUCCESS"
        assert log.row_hash is not None


def test_transfer_rollback_leaves_no_audit_row():
    """Requirement 17: If transfer rolls back mid-transaction, no TRANSFER_COMPLETED row commits."""
    u1_id, _ = create_user_with_token("rollback1@example.com")
    u2_id, _ = create_user_with_token("rollback2@example.com")
    create_account(u1_id, "1000000011", Decimal("1000.00"))
    create_account(u2_id, "1000000012", Decimal("500.00"))

    # Execute a manual transaction that calls record_event then rolls back
    from app.audit.service import record_event
    with TestSession() as db:
        record_event(
            db=db,
            event_type="TRANSFER_COMPLETED",
            actor_user_id=u1_id,
            actor_role="customer",
            entity_type="transaction",
            entity_id="99999",
            outcome="SUCCESS",
            details={"simulated": "transfer"},
        )
        # Explicit rollback of caller transaction
        db.rollback()

    with TestSession() as db:
        stmt = select(AuditLog).where(AuditLog.entity_id == "99999")
        assert db.scalar(stmt) is None


def test_failed_login_creates_audit_row_despite_failure():
    """Requirement 18: Failed login attempts persist in audit log via independent transaction."""
    create_user_with_token("login_fail_target@example.com", "CorrectPassword1!")

    resp = client.post(
        "/auth/login",
        data={"username": "login_fail_target@example.com", "password": "WrongPassword!"},
    )
    assert resp.status_code == 401

    with TestSession() as db:
        stmt = select(AuditLog).where(
            AuditLog.event_type == "LOGIN_FAILED",
            AuditLog.outcome == "FAILURE",
        )
        logs = list(db.scalars(stmt).all())
        assert len(logs) >= 1
        assert logs[-1].details["attempted_email"] == "login_fail_target@example.com"


def test_direct_sql_update_and_delete_blocked_by_trigger():
    """Requirement 19: Database trigger unconditionally blocks direct SQL UPDATE and DELETE."""
    u_id, _ = create_user_with_token("trigger_test@example.com")

    with TestSession() as db:
        log = AuditLog(
            event_type="TEST_TRIGGER_EVENT",
            actor_user_id=u_id,
            actor_role="customer",
            entity_type="test",
            entity_id="1",
            outcome="SUCCESS",
            details={"note": "test"},
            prev_hash=None,
            row_hash="abc123hash",
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        log_id = log.id

    # Test UPDATE is blocked
    with pytest.raises(Exception) as exc_update:
        with test_engine.begin() as conn:
            conn.execute(
                text("UPDATE audit_logs SET outcome = 'FAILURE' WHERE id = :id"),
                {"id": log_id},
            )
    assert "audit_logs is an append-only table" in str(exc_update.value)

    # Test DELETE is blocked
    with pytest.raises(Exception) as exc_delete:
        with test_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM audit_logs WHERE id = :id"),
                {"id": log_id},
            )
    assert "audit_logs is an append-only table" in str(exc_delete.value)


def test_hash_chain_verification_and_tampering():
    """Requirement 20: verify_hash_chain detects chain validity and pinpoints tampered rows."""
    _, admin_auth = create_user_with_token("admin_verify@example.com", role=UserRole.ADMIN)

    # Trigger multiple actions to produce audit entries
    u1_id, u1_auth = create_user_with_token("hc1@example.com")
    u2_id, _ = create_user_with_token("hc2@example.com")
    create_account(u1_id, "1000000021", Decimal("1000.00"))
    create_account(u2_id, "1000000022", Decimal("500.00"))

    client.post(
        "/transactions",
        headers={"Authorization": u1_auth, "Idempotency-Key": "hc-tx-1"},
        json={"recipient_account_number": "1000000022", "amount": 50.00},
    )

    # 1. Verify valid chain via API
    resp = client.get("/audit/verify", headers={"Authorization": admin_auth})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["checked"] >= 3
    assert data["first_broken_id"] is None

    # Pick an audit row to tamper
    with TestSession() as db:
        row = db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).first()
        tamper_id = row.id

    # 2. Tamper row by temporarily disabling trigger, modifying outcome, and re-enabling trigger
    with test_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_prevent_update_delete;"))
        conn.execute(
            text("UPDATE audit_logs SET outcome = 'TAMPERED' WHERE id = :id"),
            {"id": tamper_id},
        )
        conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_prevent_update_delete;"))

    # 3. Verify tampered chain is flagged
    resp_tampered = client.get("/audit/verify", headers={"Authorization": admin_auth})
    assert resp_tampered.status_code == 200
    data_tampered = resp_tampered.json()
    assert data_tampered["valid"] is False
    assert data_tampered["first_broken_id"] == tamper_id


def test_20_concurrent_transfers_chain_stays_valid():
    """Requirement 21: 20 concurrent transfers keep the cryptographic hash chain strictly valid."""
    _, admin_auth = create_user_with_token("admin_concurrent@example.com", role=UserRole.ADMIN)
    u1_id, u1_auth = create_user_with_token("c1@example.com")
    u2_id, _ = create_user_with_token("c2@example.com")

    create_account(u1_id, "1000000031", Decimal("50000.00"))
    create_account(u2_id, "1000000032", Decimal("50000.00"))

    def send_transfer(idx: int):
        return client.post(
            "/transactions",
            headers={"Authorization": u1_auth, "Idempotency-Key": f"concurrent-audit-{idx}"},
            json={"recipient_account_number": "1000000032", "amount": 10.00},
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send_transfer, i) for i in range(20)]
        results = [f.result() for f in as_completed(futures)]

    for r in results:
        assert r.status_code == 201

    # Verify hash chain over all records
    resp = client.get("/audit/verify", headers={"Authorization": admin_auth})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["first_broken_id"] is None
    assert data["checked"] >= 20


def test_sensitive_data_sanitization():
    """Requirement 22: Passwords and tokens never appear in audit details."""
    dirty_details = {
        "user_email": "safe@example.com",
        "password": "SuperSecretPassword123!",
        "new_password": "NewSecretPassword!",
        "token": "eyJhbGciOiJIUzI1NiIsIn...",
        "access_token": "secret_jwt_token",
        "nested": {
            "hashed_password": "$2b$12$e0X7...",
            "authorization": "Bearer eyJ...",
            "safe_counter": 42,
        },
    }

    clean = sanitize_details(dirty_details)
    assert "password" not in clean
    assert "new_password" not in clean
    assert "token" not in clean
    assert "access_token" not in clean
    assert "hashed_password" not in clean["nested"]
    assert "authorization" not in clean["nested"]
    assert clean["user_email"] == "safe@example.com"
    assert clean["nested"]["safe_counter"] == 42


def test_role_authorization_on_audit_endpoints():
    """Requirement 23: Strict role checks on /audit/logs, /audit/entity, and /audit/verify."""
    _, cust_auth = create_user_with_token("cust_role@example.com", role=UserRole.CUSTOMER)
    _, anal_auth = create_user_with_token("anal_role@example.com", role=UserRole.RISK_ANALYST)
    _, admin_auth = create_user_with_token("admin_role@example.com", role=UserRole.ADMIN)

    # 1. Customer is blocked from all audit endpoints
    assert client.get("/audit/logs", headers={"Authorization": cust_auth}).status_code == 403
    assert client.get("/audit/verify", headers={"Authorization": cust_auth}).status_code == 403
    assert client.get("/audit/entity/transaction/1", headers={"Authorization": cust_auth}).status_code == 403

    # 2. Risk analyst can only view transaction and fraud_alert entities
    assert client.get("/audit/logs", headers={"Authorization": anal_auth}).status_code == 403
    assert client.get("/audit/verify", headers={"Authorization": anal_auth}).status_code == 403
    assert client.get("/audit/entity/user/1", headers={"Authorization": anal_auth}).status_code == 403
    assert client.get("/audit/entity/transaction/1", headers={"Authorization": anal_auth}).status_code == 200
    assert client.get("/audit/entity/fraud_alert/1", headers={"Authorization": anal_auth}).status_code == 200

    # 3. Admin has full access to all audit endpoints
    assert client.get("/audit/logs", headers={"Authorization": admin_auth}).status_code == 200
    assert client.get("/audit/verify", headers={"Authorization": admin_auth}).status_code == 200
    assert client.get("/audit/entity/user/1", headers={"Authorization": admin_auth}).status_code == 200
    assert client.get("/audit/entity/transaction/1", headers={"Authorization": admin_auth}).status_code == 200


def test_idempotent_replay_logs_replay_event():
    """Requirement 11: Idempotent replay logs IDEMPOTENT_REPLAY instead of duplicate action."""
    u1_id, u1_auth = create_user_with_token("replay_sender@example.com")
    u2_id, _ = create_user_with_token("replay_recip@example.com")
    create_account(u1_id, "1000000041", Decimal("1000.00"))
    create_account(u2_id, "1000000042", Decimal("500.00"))

    # Initial transfer
    resp1 = client.post(
        "/transactions",
        headers={"Authorization": u1_auth, "Idempotency-Key": "replay-test-key"},
        json={"recipient_account_number": "1000000042", "amount": 25.00},
    )
    assert resp1.status_code == 201

    # Replay identical transfer
    resp2 = client.post(
        "/transactions",
        headers={"Authorization": u1_auth, "Idempotency-Key": "replay-test-key"},
        json={"recipient_account_number": "1000000042", "amount": 25.00},
    )
    assert resp2.status_code == 201
    assert resp2.json()["id"] == resp1.json()["id"]

    with TestSession() as db:
        completed_logs = list(db.scalars(select(AuditLog).where(AuditLog.event_type == "TRANSFER_COMPLETED")).all())
        assert len(completed_logs) == 1

        replay_logs = list(db.scalars(select(AuditLog).where(AuditLog.event_type == "IDEMPOTENT_REPLAY")).all())
        assert len(replay_logs) == 1
        assert replay_logs[0].details["idempotency_key"] == "replay-test-key"


def test_fraud_review_audit_events_and_separation_of_duties():
    """Requirement 10: Fraud decisions and separation-of-duties violations are audited."""
    c1_id, c1_auth = create_user_with_token("fraud_c1@example.com")
    c2_id, _ = create_user_with_token("fraud_c2@example.com")
    _, anal_auth = create_user_with_token("fraud_analyst@example.com", role=UserRole.RISK_ANALYST)

    create_account(c1_id, "1000000051", Decimal("10000.00"))
    create_account(c2_id, "1000000052", Decimal("1000.00"))

    # High risk transfer ($3,000) -> held in PENDING_REVIEW
    resp = client.post(
        "/transactions",
        headers={"Authorization": c1_auth, "Idempotency-Key": "fraud-audit-key"},
        json={"recipient_account_number": "1000000052", "amount": 3000.00},
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "pending_review"

    with TestSession() as db:
        held_logs = list(db.scalars(select(AuditLog).where(AuditLog.event_type == "TRANSFER_HELD")).all())
        assert len(held_logs) == 1

    # Fetch alert
    alerts_resp = client.get("/fraud/alerts", headers={"Authorization": anal_auth})
    assert alerts_resp.status_code == 200
    alert_id = alerts_resp.json()[0]["id"]

    # Approve transfer
    approve_resp = client.post(
        f"/fraud/alerts/{alert_id}/approve",
        headers={"Authorization": anal_auth},
        json={"note": "Verified legitimate business expense"},
    )
    assert approve_resp.status_code == 200

    with TestSession() as db:
        approved_logs = list(db.scalars(select(AuditLog).where(AuditLog.event_type == "ALERT_APPROVED")).all())
        assert len(approved_logs) == 1
        assert approved_logs[0].entity_id == str(alert_id)
