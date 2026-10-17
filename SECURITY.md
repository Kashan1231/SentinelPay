# SentinelPay Security Posture (SECURITY.md)

This document maps SentinelPay against the **OWASP API Security Top 10 (2023)** and documents our security posture honestly: what is implemented, what is partial, and what is not applicable or missing.

---

## OWASP API Security Top 10 Mapping

| # | OWASP Risk | SentinelPay Status | Implementation | Evidence |
|---|---|---|---|---|
| API1 | **Broken Object-Level Authorization** | ✅ Implemented | Every `{id}` endpoint checks ownership: customers see only their own accounts, transactions, payments, and disputes. Admin/Risk Analyst roles bypass ownership for operational needs. | `tests/test_security.py::TestAuthorizationSweep` |
| API2 | **Broken Authentication** | ✅ Implemented | JWT-based auth with bcrypt hashing, account lockout after N failures, constant-time dummy verification for unknown emails (anti-enumeration), password policy (min 10, max 72 bytes, no email, no common passwords), token expiry enforced, inactive users rejected. | `app/auth/router.py`, `app/auth/security.py`, `tests/test_security.py::TestAccountLockout`, `tests/test_security.py::TestPasswordPolicy`, `tests/test_security.py::TestTokenSecurity` |
| API3 | **Broken Object Property Level Authorization** | ✅ Implemented | Mass-assignment prevention via `extra="forbid"` on `UserCreate` schema — attempting to set `role`, `is_active`, or `balance` via registration returns 422. Response schemas (`UserResponse`) explicitly exclude `hashed_password`. | `app/auth/schemas.py`, `tests/test_security.py::TestMassAssignment` |
| API4 | **Unrestricted Resource Consumption** | ✅ Implemented | Sliding-window rate limiting on login, registration, transactions, payments, and disputes. Request body size limit (1 MB). Per-IP and per-user scoping. 429 responses with `Retry-After` header. | `app/core/rate_limit.py`, `app/core/middleware.py`, `tests/test_security.py::TestRateLimiting`, `tests/test_security.py::TestBodySizeLimit` |
| API5 | **Broken Function Level Authorization** | ✅ Implemented | Role-based access control: `require_role()` dependency enforces ADMIN-only on audit logs, recon, user unlock; RISK_ANALYST+ADMIN on fraud alerts and staff disputes; CUSTOMER on own resources only. Authorization sweep test confirms 401/403/404 on every endpoint. | `app/auth/dependencies.py`, `tests/test_security.py::TestAuthorizationSweep` |
| API6 | **Unrestricted Access to Sensitive Business Flows** | ✅ Implemented | Idempotency keys required on transactions, payments, and disputes. Row-level locking prevents double-processing. Fraud engine holds suspicious transfers for analyst review. | `app/transactions/service.py`, `app/payments/service.py`, `tests/test_concurrency.py` |
| API7 | **Server-Side Request Forgery (SSRF)** | ⬜ Not Applicable | SentinelPay does not accept user-supplied URLs or make outbound requests to user-controlled destinations. The mock payment rail is internal only. | N/A |
| API8 | **Security Misconfiguration** | ✅ Implemented | Security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cache-Control, HSTS in production). CORS restricted to configured origins only. `/docs` and `/openapi.json` toggleable via `DOCS_ENABLED` setting. Generic 500 errors hide stack traces. JWT startup check blocks weak secrets in non-dev environments. | `app/core/middleware.py`, `app/main.py`, `tests/test_security.py::TestSecurityHeaders` |
| API9 | **Improper Inventory Management** | 🟡 Partial | API versioning is not implemented (single version `v0.1.0`). All endpoints are documented via OpenAPI/Swagger when enabled. No deprecated endpoints exist. | `app/main.py` |
| API10 | **Unsafe Consumption of APIs** | ⬜ Not Applicable | The only external integration is the mock payment rail, which is self-contained within the application. No third-party API calls are made. | N/A |

---

## Additional Security Measures

| Feature | Status | Description |
|---|---|---|
| **Append-only audit log** | ✅ Implemented | SHA-256 hash-chained, tamper-evident audit trail. DB trigger prevents UPDATE/DELETE. Verification endpoint available. |
| **Sensitive data sanitization** | ✅ Implemented | Passwords, tokens, and secrets are stripped from audit log details before persistence. |
| **Request ID tracking** | ✅ Implemented | Unique `X-Request-ID` header on every response for incident correlation. |
| **Monetary input validation** | ✅ Implemented | Amounts validated for finite values, ≤2 decimal places, positive, and sane maximum. |
| **Independent audit logging** | ✅ Implemented | Security events (login failures, lockouts, rate limits) persist even if the main transaction rolls back. |

---

## Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| **In-memory rate limiter** | Per-process storage; multi-instance deployments bypass limits across workers. | Replace `InMemorySlidingWindowStorage` with a Redis-backed implementation for production multi-worker deployments. The storage interface is already abstracted. |
| **No MFA / 2FA** | Single-factor authentication only (password). | Password policy is strict. Account lockout mitigates brute-force. MFA would be a Phase 11+ enhancement. |
| **No refresh tokens** | JWT access tokens are the only mechanism; no token rotation. | Short-lived JWTs (default 60 min). Token for deactivated users is rejected on every request. |
| **No TLS termination in-app** | HTTPS is expected to be handled by a reverse proxy (nginx, cloud load balancer), not by FastAPI directly. | HSTS header is set when `ENVIRONMENT=production`. |
| **Dispute refunds have no bank-side funding account** | Refund credits are created from nowhere — no suspense or operational-loss account is debited. | Documented as a known simplification. In a real system, a funding/suspense account would be debited. |
| **API versioning** | No URL-based versioning (`/v1/`, `/v2/`). | Single version; would be added when breaking changes are introduced. |
| **No CSRF protection** | API-only backend using Bearer tokens (not cookies), so CSRF is not applicable. | If cookie-based auth is ever added, CSRF tokens would be needed. |
