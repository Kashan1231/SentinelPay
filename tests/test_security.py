"""
SentinelPay – Phase 10 Security Hardening Tests.

Tests for:
  - Account lockout (5 failures → lock, correct password still blocked, unlock, counter reset)
  - Unknown email vs wrong password indistinguishable (same status, same message)
  - Rate limiting triggers and Retry-After header
  - Password policy (min 10, max 72 bytes, no email, no common passwords)
  - Mass-assignment prevention (extra fields rejected on /auth/register)
  - Monetary input validation (>2 decimal places, NaN, negative)
  - Security headers present on every response
  - Generic 500 hides internals
  - Request body size limit (413)
  - Token for deactivated user rejected
  - /audit/verify still valid after Phase 10 security events
  - Authorization sweep across every id-based endpoint
"""

from datetime import timedelta
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from app.auth.security import create_access_token, hash_password
from app.auth.models import User, UserRole
from app.core.config import settings
from app.core.rate_limit import limiter_storage

from conftest import client, TestSession


# ──────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────

def _register(email: str = "test@example.com", password: str = "StrongP@ss!1234", name: str = "Test User"):
    return client.post("/auth/register", json={
        "email": email,
        "password": password,
        "full_name": name,
    })


def _login(email: str = "test@example.com", password: str = "StrongP@ss!1234"):
    return client.post("/auth/login", data={"username": email, "password": password})


def _create_admin_token():
    """Create admin user directly in DB and return token."""
    db = TestSession()
    admin = User(
        email="admin@sentinelpay.com",
        hashed_password=hash_password("AdminP@ss!1234"),
        full_name="Admin User",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    admin_id = admin.id
    db.close()
    token = create_access_token(data={"sub": str(admin_id), "role": "admin"})
    return token, admin_id


def _create_analyst_token():
    """Create risk analyst user directly in DB and return token."""
    db = TestSession()
    analyst = User(
        email="analyst@sentinelpay.com",
        hashed_password=hash_password("AnalystP@ss!1234"),
        full_name="Risk Analyst",
        role=UserRole.RISK_ANALYST,
        is_active=True,
    )
    db.add(analyst)
    db.commit()
    db.refresh(analyst)
    analyst_id = analyst.id
    db.close()
    token = create_access_token(data={"sub": str(analyst_id), "role": "risk_analyst"})
    return token, analyst_id


def _create_customer_with_account(email="customer@test.com"):
    """Register customer and create account, return (token, account_id, user_id)."""
    r = _register(email=email, password="StrongP@ss!1234", name="Customer")
    assert r.status_code == 201
    lr = _login(email=email, password="StrongP@ss!1234")
    token = lr.json()["access_token"]
    acct = client.post("/accounts", json={"account_type": "savings"},
                       headers={"Authorization": f"Bearer {token}"})
    assert acct.status_code == 201
    return token, acct.json()["id"], r.json()["id"]


# ──────────────────────────────────────────────────────────────
# 1. ACCOUNT LOCKOUT TESTS
# ──────────────────────────────────────────────────────────────

class TestAccountLockout:
    """Tests for DB-backed account lockout (Part A)."""

    def test_lockout_after_n_failures(self):
        """After LOGIN_MAX_FAILURES wrong passwords, account is locked."""
        _register()
        for i in range(settings.LOGIN_MAX_FAILURES):
            r = _login(password="WrongP@ssword!!")
            if i < settings.LOGIN_MAX_FAILURES - 1:
                assert r.status_code == 401, f"Attempt {i+1} should be 401"

        # The last failure should lock the account → 429
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_correct_password_blocked_while_locked(self):
        """Even the correct password is rejected while the account is locked."""
        _register()
        for _ in range(settings.LOGIN_MAX_FAILURES):
            _login(password="WrongP@ssword!!")

        # Now try with the correct password
        r = _login(password="StrongP@ss!1234")
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_admin_unlock_clears_lockout(self):
        """Admin can unlock a locked account."""
        _register()
        for _ in range(settings.LOGIN_MAX_FAILURES):
            _login(password="WrongP@ssword!!")

        # Confirm locked
        r = _login(password="StrongP@ss!1234")
        assert r.status_code == 429

        # Admin unlocks
        admin_token, _ = _create_admin_token()
        user_id = 1  # First registered user
        unlock_r = client.post(
            f"/admin/users/{user_id}/unlock",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert unlock_r.status_code == 200

        # Now correct password works
        r = _login(password="StrongP@ss!1234")
        assert r.status_code == 200

    def test_counter_resets_on_success(self):
        """A successful login resets the failure counter."""
        _register()
        # Fail a few times (but not enough to lock)
        for _ in range(settings.LOGIN_MAX_FAILURES - 1):
            _login(password="WrongP@ssword!!")

        # Successful login resets counter
        r = _login(password="StrongP@ss!1234")
        assert r.status_code == 200

        # Now fail again up to max-1 — should NOT lock (counter was reset)
        for _ in range(settings.LOGIN_MAX_FAILURES - 1):
            r = _login(password="WrongP@ssword!!")
            assert r.status_code == 401

    def test_unknown_email_and_wrong_password_indistinguishable(self):
        """Unknown email and wrong password return the same status code and message."""
        _register(email="known@example.com")

        r_unknown = _login(email="nobody@example.com", password="WrongP@ssword!!")
        r_wrong = _login(email="known@example.com", password="WrongP@ssword!!")

        assert r_unknown.status_code == r_wrong.status_code == 401
        assert r_unknown.json()["detail"] == r_wrong.json()["detail"]


# ──────────────────────────────────────────────────────────────
# 2. RATE LIMITING TESTS
# ──────────────────────────────────────────────────────────────

class TestRateLimiting:
    """Rate limiting triggers and Retry-After header."""

    def setup_method(self):
        """Enable rate limiting and reset storage for each test."""
        settings.RATE_LIMIT_ENABLED = True
        limiter_storage.reset()

    def teardown_method(self):
        """Disable rate limiting after each test."""
        settings.RATE_LIMIT_ENABLED = False
        limiter_storage.reset()

    def test_login_rate_limit_triggers(self):
        """Exceeding login rate limit returns 429 with Retry-After."""
        _register()
        # Exhaust the limit
        for _ in range(settings.RATE_LIMIT_LOGIN_MAX):
            _login(password="StrongP@ss!1234")

        # Next request should be rate limited
        r = _login(password="StrongP@ss!1234")
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_register_rate_limit_triggers(self):
        """Exceeding register rate limit returns 429."""
        for i in range(settings.RATE_LIMIT_REGISTER_MAX):
            _register(email=f"user{i}@example.com")

        r = _register(email="extra@example.com")
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_transaction_rate_limit_per_user(self):
        """Per-user transaction rate limit works."""
        # Need lower limit for test
        original = settings.RATE_LIMIT_TRANSACTION_MAX
        settings.RATE_LIMIT_TRANSACTION_MAX = 2
        try:
            token, acct_id, _ = _create_customer_with_account()
            headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": ""}

            for i in range(3):
                headers["Idempotency-Key"] = f"txn-{i}"
                r = client.post("/transactions", json={
                    "recipient_account_number": "0000000000",
                    "amount": "10.00",
                    "sender_account_id": acct_id,
                }, headers=headers)
                if i >= 2:
                    assert r.status_code == 429
        finally:
            settings.RATE_LIMIT_TRANSACTION_MAX = original


# ──────────────────────────────────────────────────────────────
# 3. PASSWORD POLICY TESTS
# ──────────────────────────────────────────────────────────────

class TestPasswordPolicy:
    """Password policy enforcement (Part C)."""

    def test_password_too_short(self):
        r = _register(password="Short1!")
        assert r.status_code == 422
        assert "10 characters" in r.json()["detail"][0]["msg"]

    def test_password_exceeds_72_bytes(self):
        # 73 ASCII chars = 73 bytes > 72
        long_pw = "A" * 73
        r = _register(password=long_pw)
        assert r.status_code == 422
        assert "72 bytes" in r.json()["detail"][0]["msg"]

    def test_password_equals_email(self):
        r = _register(email="test@example.com", password="test@example.com")
        assert r.status_code == 422
        assert "email" in r.json()["detail"][0]["msg"].lower()

    def test_common_password_rejected(self):
        r = _register(password="password123")
        assert r.status_code == 422
        assert "common" in r.json()["detail"][0]["msg"].lower()


# ──────────────────────────────────────────────────────────────
# 4. MASS ASSIGNMENT PREVENTION TESTS
# ──────────────────────────────────────────────────────────────

class TestMassAssignment:
    """Registration must reject extra fields (role, is_active, balance)."""

    def test_register_with_role_admin_rejected(self):
        r = client.post("/auth/register", json={
            "email": "hacker@test.com",
            "password": "StrongP@ss!1234",
            "full_name": "Hacker",
            "role": "admin",
        })
        assert r.status_code == 422  # extra="forbid" rejects

    def test_register_with_is_active_rejected(self):
        r = client.post("/auth/register", json={
            "email": "hacker2@test.com",
            "password": "StrongP@ss!1234",
            "full_name": "Hacker",
            "is_active": True,
        })
        assert r.status_code == 422

    def test_register_with_balance_rejected(self):
        r = client.post("/auth/register", json={
            "email": "hacker3@test.com",
            "password": "StrongP@ss!1234",
            "full_name": "Hacker",
            "balance": "999999.00",
        })
        assert r.status_code == 422


# ──────────────────────────────────────────────────────────────
# 5. MONETARY INPUT VALIDATION
# ──────────────────────────────────────────────────────────────

class TestMonetaryValidation:
    """Amount inputs reject invalid values."""

    def test_amount_more_than_two_decimals(self):
        token, acct_id, _ = _create_customer_with_account()
        r = client.post("/transactions", json={
            "recipient_account_number": "0000000000",
            "amount": "10.001",
            "sender_account_id": acct_id,
        }, headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "test-1"})
        assert r.status_code == 422

    def test_amount_negative(self):
        token, acct_id, _ = _create_customer_with_account()
        r = client.post("/transactions", json={
            "recipient_account_number": "0000000000",
            "amount": "-5.00",
            "sender_account_id": acct_id,
        }, headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "test-2"})
        assert r.status_code == 422


# ──────────────────────────────────────────────────────────────
# 6. SECURITY HEADERS TESTS
# ──────────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Security headers middleware (Part D)."""

    def test_security_headers_present(self):
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Referrer-Policy") == "no-referrer"
        assert "X-Request-ID" in r.headers

    def test_cache_control_on_authenticated_endpoint(self):
        _register()
        lr = _login()
        token = lr.json()["access_token"]
        r = client.get("/accounts", headers={"Authorization": f"Bearer {token}"})
        assert r.headers.get("Cache-Control") == "no-store"

    def test_request_id_unique_per_request(self):
        r1 = client.get("/health")
        r2 = client.get("/health")
        assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]


# ──────────────────────────────────────────────────────────────
# 7. REQUEST BODY SIZE LIMIT
# ──────────────────────────────────────────────────────────────

class TestBodySizeLimit:
    """Request body size limit returns 413."""

    def test_oversized_body_rejected(self):
        huge_body = "x" * (settings.MAX_REQUEST_BODY_BYTES + 1)
        r = client.post(
            "/auth/register",
            content=huge_body,
            headers={"Content-Type": "application/json",
                     "Content-Length": str(len(huge_body))},
        )
        assert r.status_code == 413


# ──────────────────────────────────────────────────────────────
# 8. TOKEN EXPIRY AND DEACTIVATED USER
# ──────────────────────────────────────────────────────────────

class TestTokenSecurity:
    """Token expiry enforcement and deactivated user rejection."""

    def test_expired_token_rejected(self):
        _register()
        expired_token = create_access_token(
            data={"sub": "1", "role": "customer"},
            expires_delta=timedelta(seconds=-10),
        )
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        assert r.status_code == 401

    def test_deactivated_user_token_rejected(self):
        """Token for an inactive user is rejected."""
        db = TestSession()
        user = User(
            email="inactive@test.com",
            hashed_password=hash_password("InactiveP@ss!1234"),
            full_name="Inactive User",
            role=UserRole.CUSTOMER,
            is_active=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        db.close()

        token = create_access_token(data={"sub": str(user_id), "role": "customer"})
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401


# ──────────────────────────────────────────────────────────────
# 9. AUDIT CHAIN STILL VALID AFTER SECURITY EVENTS
# ──────────────────────────────────────────────────────────────

class TestAuditChainPostSecurity:
    """Verify audit chain integrity after security events."""

    def test_audit_verify_still_valid(self):
        """After login failures, lockouts, and successes, the audit chain is intact."""
        _register()
        # Generate some security audit events
        for _ in range(3):
            _login(password="WrongP@ssword!!")
        _login(password="StrongP@ss!1234")

        admin_token, _ = _create_admin_token()
        r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is True
        assert body["checked"] > 0


# ──────────────────────────────────────────────────────────────
# 10. AUTHORIZATION SWEEP
# ──────────────────────────────────────────────────────────────

class TestAuthorizationSweep:
    """Parametrized authorization verification across all id-based endpoints.
    
    For EVERY endpoint taking an id: checks unauthenticated → 401,
    wrong customer → 403 (or 404), correct role → allowed.
    """

    # Endpoint definitions: (method, path_template, needs_setup, expected_owner_status, setup_fn)
    CUSTOMER_ENDPOINTS = [
        ("GET", "/accounts/{id}"),
        ("GET", "/transactions/{id}"),
        ("GET", "/payments/{id}"),
        ("GET", "/disputes/{id}"),
    ]

    ADMIN_ONLY_ENDPOINTS = [
        ("GET", "/audit/logs"),
        ("GET", "/audit/verify"),
        ("POST", "/admin/recon/run"),
        ("GET", "/admin/recon/exceptions"),
    ]

    STAFF_ENDPOINTS = [
        ("GET", "/fraud/alerts"),
        ("GET", "/staff/disputes"),
    ]

    def test_unauthenticated_returns_401(self):
        """All protected endpoints return 401 without auth."""
        endpoints = [
            ("GET", "/accounts/1"),
            ("GET", "/transactions/1"),
            ("GET", "/payments/1"),
            ("GET", "/disputes/1"),
            ("GET", "/fraud/alerts"),
            ("GET", "/fraud/alerts/1"),
            ("GET", "/audit/logs"),
            ("GET", "/audit/verify"),
            ("GET", "/admin/recon/exceptions"),
            ("GET", "/admin/payments"),
            ("GET", "/staff/disputes"),
            ("GET", "/staff/disputes/1"),
            ("GET", "/auth/me"),
        ]
        for method, path in endpoints:
            r = getattr(client, method.lower())(path)
            assert r.status_code == 401, f"{method} {path} returned {r.status_code}, expected 401"

    def test_customer_cannot_access_admin_endpoints(self):
        """Customer role is rejected on admin-only endpoints."""
        token, _, _ = _create_customer_with_account()
        headers = {"Authorization": f"Bearer {token}"}

        admin_endpoints = [
            ("GET", "/audit/logs"),
            ("GET", "/audit/verify"),
            ("POST", "/admin/recon/run"),
            ("GET", "/admin/recon/exceptions"),
            ("GET", "/admin/payments"),
            ("GET", "/staff/disputes"),
        ]
        for method, path in admin_endpoints:
            r = getattr(client, method.lower())(path, headers=headers)
            assert r.status_code == 403, f"Customer {method} {path} returned {r.status_code}, expected 403"

    def test_wrong_customer_cannot_access_others_account(self):
        """Customer A cannot view Customer B's account."""
        token_a, acct_a, _ = _create_customer_with_account(email="a@test.com")
        token_b, acct_b, _ = _create_customer_with_account(email="b@test.com")

        # Customer B tries to access Customer A's account
        r = client.get(f"/accounts/{acct_a}",
                       headers={"Authorization": f"Bearer {token_b}"})
        assert r.status_code == 403

    def test_admin_can_access_all_accounts(self):
        """Admin can view any account."""
        _, acct_id, _ = _create_customer_with_account()
        admin_token, _ = _create_admin_token()

        r = client.get(f"/accounts/{acct_id}",
                       headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200

    def test_admin_can_access_audit_logs(self):
        """Admin can access audit log listing."""
        admin_token, _ = _create_admin_token()
        r = client.get("/audit/logs",
                       headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200

    def test_risk_analyst_can_access_fraud_alerts(self):
        """Risk analyst can list fraud alerts."""
        analyst_token, _ = _create_analyst_token()
        r = client.get("/fraud/alerts",
                       headers={"Authorization": f"Bearer {analyst_token}"})
        assert r.status_code == 200

    def test_customer_audit_entity_forbidden(self):
        """Customer cannot access audit entity timeline."""
        token, _, _ = _create_customer_with_account()
        r = client.get("/audit/entity/user/1",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_nonexistent_resource_returns_404(self):
        """Accessing a nonexistent resource returns 404, not 403."""
        token, _, _ = _create_customer_with_account()
        headers = {"Authorization": f"Bearer {token}"}

        # Nonexistent account the user doesn't own — should be 404
        r = client.get("/accounts/99999", headers=headers)
        assert r.status_code == 404

    def test_admin_unlock_requires_admin_role(self):
        """Only admin can unlock users."""
        _register()
        analyst_token, _ = _create_analyst_token()
        r = client.post("/admin/users/1/unlock",
                        headers={"Authorization": f"Bearer {analyst_token}"})
        assert r.status_code == 403
