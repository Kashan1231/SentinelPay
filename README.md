# SentinelPay

A simulated fintech transaction platform with explainable fraud detection, tamper-evident auditing, reconciliation, and automated dispute resolution with SLAs, built to demonstrate the backend patterns real payment systems use: atomic transactions, idempotency, role-based authorization, explainable rule-based fraud scoring, immutable audit logging, external payment rail simulation, and a full operational resolution layer.

> **Current phase: 10 - Security Hardening & Production Readiness**  
> Comprehensive OWASP API Security Top 10 defenses, sliding-window rate limiting, account lockout with anti-enumeration protection, strict password policy & monetary validation, mass-assignment guards, security headers middleware, request body size limits, error masking, production environment guards, and 143 tests passing against PostgreSQL native service.

---

## Quick Start

### Local Setup (PostgreSQL 16 - Windows Service)

```bash
# 1. Apply all database migrations
python -m alembic upgrade head

# 2. (Dev only) Seed demo users, funded accounts, and mock billers
python scripts/seed.py

# 3. Start the FastAPI development server
python -m uvicorn app.main:app
```

Open **http://127.0.0.1:8000/docs** to explore the API interactively.

---

## Phase 10: Security Hardening & Production Readiness

Payment APIs handle critical financial assets and sensitive personal data. Phase 10 transforms SentinelPay into a production-grade backend with defense-in-depth security mitigations aligned with the **OWASP API Security Top 10 (2023)**.

See full mapping and risk matrix in [SECURITY.md](file:///c:/Users/KASHAN/OneDrive/Desktop/SentinelPay/SECURITY.md).

---

### Core Security Mitigations

1. **Account Lockout & Anti-Enumeration (API2: Broken Authentication)**:
   - **Lockout Policy**: After 5 consecutive failed login attempts, an account is locked (`is_locked=True`, `locked_until` set). Further login attempts are immediately rejected, even with the correct password.
   - **Admin Unlock**: Administrators can manually unlock accounts via `POST /admin/users/{id}/unlock`, resetting `failed_login_attempts` to 0. Successful logins also reset the counter.
   - **Anti-Enumeration Protection**: Login responses return an identical error message (`"Invalid email or password"`) and status (`401`) whether the email exists or not. Unknown emails trigger a constant-time dummy password hash check to prevent timing-based user enumeration attacks.

2. **Sliding-Window Rate Limiting (API4: Unrestricted Resource Consumption)**:
   - In-memory sliding-window log rate limiter with scoped tiers:
     - `auth:login` (per IP): 5 requests / 60 seconds
     - `auth:register` (per IP): 3 requests / 60 seconds
     - `tx:create` (per user): 10 requests / 60 seconds
     - `payment:create` (per user): 5 requests / 60 seconds
     - `dispute:create` (per user): 3 requests / 60 seconds
   - Excess requests receive `429 Too Many Requests` with a compliant `Retry-After` header indicating seconds until the window clears.
   - Abstracted storage interface (`SlidingWindowStorage`) allows seamless drop-in replacement with Redis for multi-instance deployments.

3. **Input Validation & Monetary Guardrails (API3 & API6)**:
   - **Password Policy**: Minimum 10 characters, maximum 72 bytes (preventing bcrypt truncation attacks), disallowed if equal to or containing the email username, disallowed if on top common password blacklist.
   - **Strict Monetary Decimal**: `MoneyDecimal` validator rejects amounts with more than 2 decimal places, negative or zero amounts, non-finite values (NaN / Inf), and amounts exceeding platform caps.
   - **Mass Assignment Prevention**: Strict Pydantic models with `extra="forbid"` on registration and transfer schemas prevent injection of protected fields like `role`, `is_active`, or `balance`.

4. **Security Middleware & Defensive Headers (API8: Security Misconfiguration)**:
   - **Defensive Headers**: Every HTTP response includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.
   - **Cache Control**: Authenticated endpoints automatically receive `Cache-Control: no-store, no-cache, must-revalidate` to prevent intermediary caching of sensitive financial data.
   - **HSTS**: `Strict-Transport-Security: max-age=31536000; includeSubDomains` applied automatically when `ENVIRONMENT=production`.
   - **Traceability**: Unique `X-Request-ID` attached to all requests and responses for end-to-end audit and incident correlation.
   - **Body Size Limiter**: Request bodies exceeding 1 MB are rejected with `413 Request Entity Too Large` before buffering into memory.
   - **Global Error Masking**: Unhandled exceptions (500) return a sanitized error message and request ID; internal stack traces, database schema details, and SQL queries are never leaked to clients.

5. **Production Environment Safety**:
   - **Docs Toggle**: Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI spec (`/openapi.json`) can be toggled via `DOCS_ENABLED` (disabled by default in production).
   - **JWT Secret Validation**: Startup lifespan hook refuses to boot in `production` or `staging` if `SECRET_KEY` remains set to development default or is shorter than 32 characters.

---

## Phase 9: Resolution Layer (Reconciliation & Disputes)

In banking and payment operations, failures are inevitable: network partitions, biller crashes, and race conditions cause ledger discrepancies. The resolution layer solves both sides of this problem:
1. **Reconciliation (Proactive Detection)**: Finds silent discrepancies nobody reported by comparing internal ledgers against counterparty rail records.
2. **Disputes & SLAs (Customer-Reported Resolution)**: Solves the "wait 45 days" customer nightmare by converting customer grievances into tracked cases with strict SLA deadlines, automated escalation sweeps, and deterministic single-credit refunds.

---

### Reconciliation Exception Matrix

Reconciliation runs via `POST /admin/recon/run` (admin only). It performs read-only set comparisons between SentinelPay's `payments` table and the counterparty's `rail_records`.

| Exception Type | What It Means | Root Cause / Real-World Scenario | Administrative Action Required |
|---|---|---|---|
| **`MISSING_AT_BILLER`** | SentinelPay shows `SETTLED`, but rail has no record (or shows `FAILED`). | Payment debited customer, dropped in-flight or lost by counterparty before recording. | Contact counterparty ops to verify funds receipt; manually settle at biller or trigger customer refund. |
| **`ORPHAN_RAIL_RECORD`** | Rail shows `SETTLED`, but SentinelPay has no payment record matching reference. | Offline transaction, out-of-band merchant settlement, or dropped database write. | Investigate billing file, locate origin account, create missing ledger entry or request biller return. |
| **`STATUS_MISMATCH`** | Statuses disagree: SentinelPay shows `REVERSED` / `FAILED` while rail shows `SETTLED`, or vice-versa. | **The classic money-loss case**: Customer was refunded after timeout, but the biller settled anyway. | Contact customer/merchant to recover duplicate credit, or resolve with accounting write-off. |
| **`AMOUNT_MISMATCH`** | Same reference exists in both systems, but ledger amounts differ. | Currency conversion error, biller surcharge applied unexpectedly, or rounding discrepancy. | Adjust ledger difference via adjustment ledger or issue partial credit/debit. |
| **`SUSPECTED_DUPLICATE`** | Same user, same biller, same amount created within 60s with different rail references. | User double-clicked or retried rapidly with different idempotency keys. | Analyst reviews both payments to determine if biller received double payment; refund if verified duplicate. |

> ⚠️ **Design Principle: Why Reconciliation NEVER Moves Money Automatically**  
> Reconciliation is an observation and detection tool, not an execution engine. Discrepancies between independent ledgers frequently arise from network delays, clock skew, manual adjustments, or multi-party settlements. Moving money or changing payment statuses automatically on recon discrepancies would risk compounding accounting errors or issuing unauthorized debits/credits. Instead, human operators must review each exception and explicitly record an audited resolution note (`POST /admin/recon/exceptions/{id}/resolve`).

---

### Dispute Lifecycle & SLA State Machine

A dispute is a tracked case, not a casual customer support ticket. It features a unique case reference (`DSP-XXXX`), category-driven SLA due date, assignable staff ownership, timeline privacy, and automated escalation.

```
                  ┌──────────────┐
                  │     OPEN     │◄───────────────────┐
                  └───┬──────┬───┘                    │
                      │      │                        │
       assign / begin │      │ SLA overdue            │
                      ▼      ▼                        │
          ┌──────────────────────┐                    │
          │    INVESTIGATING     │                    │
          └───┬──────────────┬───┘                    │
              │              │                        │
              │              │ SLA overdue            │
              ▼              ▼                        │
  ┌──────────────────────┐ ┌──────────────┐           │
  │  AWAITING_CUSTOMER   │ │  ESCALATED   │───────────┘
  └───┬──────────────────┘ └───┬──────────┘
      │                        │
      └───────────┬────────────┘
                  │
      ┌───────────┴───────────┐
      ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│ RESOLVED_REFUNDED│    │RESOLVED_REJECTED │
└──────────────────┘    └──────────────────┘
```

#### Allowed Dispute State Transitions

- `OPEN` → `INVESTIGATING` | `AWAITING_CUSTOMER` | `ESCALATED` | `RESOLVED_REJECTED`
- `INVESTIGATING` → `AWAITING_CUSTOMER` | `ESCALATED` | `RESOLVED_REFUNDED` | `RESOLVED_REJECTED`
- `AWAITING_CUSTOMER` → `INVESTIGATING` | `ESCALATED` | `RESOLVED_REJECTED`
- `ESCALATED` → `INVESTIGATING` | `RESOLVED_REFUNDED` | `RESOLVED_REJECTED`
- `RESOLVED_REFUNDED` → *Terminal state* (Cannot be modified or refunded again)
- `RESOLVED_REJECTED` → *Terminal state* (Cannot be reopened)

---

### SLA Deadlines & Escalation Sweep

1. **Configurable Category SLAs**:
   - `DUPLICATE_DEBIT`: 24 hours (86,400s)
   - `PAID_BUT_NOT_CREDITED`: 48 hours (172,800s)
   - `UNAUTHORIZED`: 12 hours (43,200s)
   - `OTHER`: 72 hours (259,200s)
2. **Automated Escalation Sweep**:
   `POST /admin/disputes/escalation-sweep` (or `python scripts/escalate_disputes.py`) scans for unresolved disputes where `NOW() >= sla_due_at + DISPUTE_ESCALATION_GRACE_SECONDS`.
   - Uses row locking with `with_for_update(skip_locked=True)` for concurrent-safe processing.
   - Transitions dispute status to `ESCALATED`, increments `escalation_level`, logs an internal `DisputeEvent`, and writes an immutable audit row (`DISPUTE_ESCALATED`).
   - Running the sweep multiple times does not duplicate escalation for the same level.

---

### Single Refund Guarantee (Database UNIQUE Constraint)

When an analyst or admin approves a refund via `POST /staff/disputes/{id}/resolve-refund`:
1. **Deterministic Lock Ordering**: Row locks are acquired in consistent order (dispute row first, then sender account row) to prevent deadlocks under concurrent requests.
2. **Backstopped by DB Unique Constraint**:
   A dedicated `dispute_refunds` table stores `(dispute_id UNIQUE, account_id, amount, created_at)`. Even if two concurrent requests race past application checks, PostgreSQL enforces that **only one refund record can ever be committed for a dispute**.
3. **Pre-condition Validation**:
   - If the dispute is already resolved or refunded -> returns `409 Conflict`.
   - If the payment was already `REVERSED` (refunded by recovery sweep) -> returns `409 Conflict`.
4. **All-or-Nothing Atomic Execution**: Balance credit, dispute state transition to `RESOLVED_REFUNDED`, `dispute_refunds` insertion, customer-visible timeline event, and audit log `DISPUTE_REFUNDED` all commit together in a single atomic database transaction.

> 💡 **Interview Note & Architectural Limitation: Suspense / Operational Loss Account**  
> In this simulation, the dispute refund directly credits the customer's account balance. In a production double-entry banking core, money cannot be created from thin air: every customer credit is balanced by a corresponding debit to an internal bank general-ledger account (e.g. *Operational Dispute Loss* or *Biller Settlement Suspense Account*). SentinelPay models the customer credit, state transition, and DB-level idempotency backstop; internal multi-legged general-ledger accounting across bank suspense accounts is an architectural extension.

---

### Separation of Duties & Customer Privacy

1. **Separation of Duties**:
   A staff member (risk analyst or admin) who is the customer on a dispute **cannot assign, investigate, or resolve their own dispute**. Any attempt returns `403 Forbidden` and writes an independent security audit row (`ACCESS_DENIED_SEPARATION_OF_DUTIES`).
2. **Customer Timeline Privacy**:
   When customers query `GET /disputes` or `GET /disputes/{id}`, only events with `visible_to_customer=True` are returned. Internal analyst investigative notes, fraud scoring details, and counterparty communication notes are strictly stripped.

---

## Phase 8: Simulated External Payment Rail

In real-world payment networks (e.g. 1LINK, RAAST, Visa Direct), payments leave our internal ledger and enter an external counterparty's system (a utility company, merchant, or biller). The external rail can delay, decline, crash, or drop connections.

### Core Concepts

1. **A Timeout is NOT a Failure**:
   If an external rail call times out, we cannot determine whether the biller processed the payment. Marking it `FAILED` and refunding immediately causes unbacked credit; retrying immediately causes double debits. SentinelPay moves timed-out payments to `UNKNOWN` and uses status inquiries to resolve ground truth before moving money.

2. **The 3-Step Pattern (Never Hold Locks Across Network Calls)**:
   - **Step 1 (Initiate)**: Validate limits, acquire row lock on sender account, debit balance, persist `Payment` as `PROCESSING`, write `PAYMENT_INITIATED` audit log. **COMMIT**.
   - **Step 2 (Rail Call)**: Call external biller rail with **NO database transaction or row lock held open**.
   - **Step 3 (Apply Outcome)**: Open a **new transaction**, acquire row lock on the payment row, apply outcome (`SETTLED`, `FAILED` + refund, or `UNKNOWN`).
   - *Why this matters*: If a biller experiences high latency (e.g. 30-second delays) or is offline, holding DB connection pool slots and account row locks would freeze user accounts and exhaust server resources. If SentinelPay crashes between Step 1 and Step 3, the payment remains safely in `PROCESSING` on disk, ready to be recovered by the sweep job.

3. **Separate Ledger Ownership**:
   Mock billers maintain their own table (`rail_records`) completely separate from SentinelPay's `payments` table. Status inquiry `get_status(rail_reference)` queries the biller's ledger to discover what actually happened.

---

### Payment State Machine

```
               ┌───────────────────────┐
               │      PROCESSING       │
               └───┬───────┬───────┬───┘
                   │       │       │
       ┌───────────┘       │       └───────────┐
       ▼                   ▼                   ▼
 ┌───────────┐       ┌───────────┐       ┌───────────┐
 │  SETTLED  │       │  UNKNOWN  │       │  FAILED   │
 └─────┬─────┘       └───┬───┬───┘       └─────┬─────┘
       │                 │   │                 │
       │                 │   │ refund step     │ refund step
       │                 │   ▼                 ▼
       │                 │  ┌───────────────────────┐
       │                 │  │       REVERSED        │
       │                 │  └──────────┬────────────┘
       │                 │             │
       ▼                 ▼             │ late SETTLED
 ┌───────────────────────────────────┐ │
 │        NEEDS_INVESTIGATION        │◄┘
 └───────────────────────────────────┘
```

#### Allowed Payment State Transitions

| From Status | To Status | Trigger / Mechanism |
|---|---|---|
| `PROCESSING` | `SETTLED` | Biller confirms payment settled immediately (Step 3). |
| `PROCESSING` | `FAILED` | Biller declines payment immediately (Step 3). |
| `PROCESSING` | `UNKNOWN` | Rail call times out (Step 3), or sweep discovers stuck `PROCESSING` payment. |
| `UNKNOWN` | `SETTLED` | Background sweep queries rail and receives `SETTLED`. |
| `UNKNOWN` | `FAILED` | Background sweep queries rail: receives `FAILED` or reaches max inquiries (`PAYMENT_MAX_INQUIRIES`). |
| `UNKNOWN` | `NEEDS_INVESTIGATION` | Manual escalation or indeterminate discrepancy. |
| `FAILED` | `REVERSED` | Automatic single refund credited back to sender account. |
| `SETTLED` | `NEEDS_INVESTIGATION` | Disputed settlement or offline chargeback. |
| `REVERSED` | `NEEDS_INVESTIGATION` | **Late Settlement**: Biller confirms settlement *after* SentinelPay already refunded the customer. Requires human review to prevent double-credit loss. |

---

### External Rail Failure Modes

| Failure Mode | What Happens at Rail | Step 3 Immediate Outcome | Recovery Sweep Action | Final Balance Effect |
|---|---|---|---|---|
| **`OK`** | Rail records `SETTLED` in `rail_records`. | Moves to `SETTLED`. Logs `PAYMENT_SETTLED`. | None needed (already final). | Debited once. |
| **`DECLINE`** | Rail records `FAILED` in `rail_records`. | Moves to `FAILED`, executes refund `FAILED → REVERSED`. Logs `PAYMENT_FAILED` & `PAYMENT_REVERSED`. | None needed (already final). | Balance unchanged (debited then refunded). |
| **`TIMEOUT_AFTER_PROCESS`** | Rail records `SETTLED` in `rail_records`, then network disconnects (`RailTimeout`). | Moves to `UNKNOWN`. Logs `PAYMENT_UNKNOWN`. **No blind refund or retry.** | Sweep queries `get_status(rail_reference)`. Rail reports `SETTLED`. Moves `UNKNOWN → SETTLED`. | Debited once (biller received funds, customer bill paid). |
| **`TIMEOUT_BEFORE_PROCESS`** | Rail never receives request (no record created), network disconnects (`RailTimeout`). | Moves to `UNKNOWN`. Logs `PAYMENT_UNKNOWN`. **No blind refund or retry.** | Sweep queries `get_status()`, gets `NOT_FOUND`. Increments `attempts_count`. Upon reaching `PAYMENT_MAX_INQUIRIES` (3), moves `FAILED → REVERSED` with refund. | Balance unchanged (refunded back to customer). |

---

### Recovery & Sweep Architecture

1. **Stuck Payment Detection**:
   `POST /admin/payments/sweep` (or `python scripts/sweep_payments.py`) selects payments in `PROCESSING` or `UNKNOWN` with `updated_at <= NOW() - PAYMENT_STUCK_AFTER_SECONDS` (default: 120s).
   - If a payment is stuck in `PROCESSING`, the server crashed mid-flow: sweep transitions it to `UNKNOWN` first, then calls `resolve_unknown`.
2. **Concurrent Sweep Safety**:
   - Queries use `with_for_update(skip_locked=True)` so multiple worker sweeps or threads never compete for the same row.
   - Refund step checks status under row lock and executes `FAILED → REVERSED`. Because the state machine strictly disallows transitioning out of `REVERSED`, duplicate refunds are impossible.
3. **Late Settlement Protection**:
   If the rail later reports `SETTLED` for a payment that was already `REVERSED` (customer already refunded), the system flags it as `NEEDS_INVESTIGATION` with audit trail `PAYMENT_NEEDS_INVESTIGATION`. It never auto-resolves this case.
4. **Idempotency Protection**:
   `POST /payments` requires an `Idempotency-Key` header. Replays return the cached response immediately and log `IDEMPOTENT_REPLAY` without debiting.

---

## Phase 7: Tamper-Evident Audit Log

The transactions ledger tracks current state. The audit log explains **who did what, when, and with what result**.

### Core Guarantees

1. **Append-Only at Database Engine Level**:
   Application code only issues `INSERT`. Furthermore, a PostgreSQL trigger (`BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW`) raises a database exception on any `UPDATE` or `DELETE` attempt. The immutability guarantee does not depend on app code behaving.

2. **Dual-Path Transaction Architecture**:
   - **Same-Transaction Writes**: For successful actions (money transfer completed or held, user registered, account created, alert reviewed), the audit row is written inside the **caller's active database transaction** without committing. If the business operation rolls back, the audit row rolls back with it. The log can never state that money moved when the transaction actually rolled back.
   - **Independent Short-Lived Writes**: For security rejections (wrong passwords, limit exceeded, insufficient funds, separation-of-duties violations), events must be preserved even though the main action is aborted. These are written and committed in an **independent short session** so security incident trails cannot be erased by client error rollbacks.

3. **Tamper-Evident Hash Chain**:
   Every row stores a cryptographic pointer `prev_hash` (the previous row's SHA-256 hash) and its own `row_hash` computed over canonicalized fields (`prev_hash`, `event_type`, `actor_user_id`, `actor_role`, `entity_type`, `entity_id`, `outcome`, sanitized `details`, `ip_address`, `created_at`).
   If an attacker or DBA directly tampers with any row's contents, every subsequent hash in the chain breaks. The `/audit/verify` endpoint walks the chain, compares signatures, and identifies the exact broken row ID.

4. **Concurrent Chain Consistency (Advisory Locking)**:
   Under concurrent transfer requests, multiple worker threads could simultaneously read the same latest hash as their `prev_hash`, causing the chain to fork/branch. SentinelPay acquires a transaction-level PostgreSQL advisory lock (`pg_advisory_xact_lock`) before reading the tail hash. This serializes chain appending at the transaction boundary without deadlocking account row locks.

---

## Audit Event Reference

| Event Type | Trigger | Actor | Entity Type | Outcome | Details Logged | Write Path |
|------------|---------|-------|-------------|---------|----------------|------------|
| `USER_REGISTERED` | User registers via `/auth/register` | User ID | `user` | `SUCCESS` | `email`, `role` | Same transaction |
| `LOGIN_SUCCESS` | Successful password login | User ID | `user` | `SUCCESS` | `email` | Same transaction |
| `LOGIN_FAILED` | Bad password or unknown email | `null` / User ID | `user` | `FAILURE` | `attempted_email` | Independent session |
| `ACCOUNT_CREATED` | New account created via `/accounts` | User ID | `account` | `SUCCESS` | `account_number`, `type`, `balance` | Same transaction |
| `TRANSFER_COMPLETED` | Transfer executes atomically | User ID | `transaction` | `SUCCESS` | `transaction_ref`, sender/recipient, `amount`, `risk_score` | Same transaction |
| `TRANSFER_HELD` | HIGH-risk transfer held | User ID | `transaction` | `SUCCESS` | `transaction_ref`, `amount`, `risk_score`, `risk_level` | Same transaction |
| `TRANSFER_REJECTED_LIMIT` | Exceeds single or daily limit | User ID | `transaction` | `DENIED` | `amount`, `limit_type`, `limit`, reason | Independent session |
| `TRANSFER_FAILED` | Insufficient sender balance | User ID | `transaction` | `FAILURE` | `amount`, reason | Independent session |
| `IDEMPOTENT_REPLAY` | Cached response replayed | User ID | `transaction` | `SUCCESS` | `idempotency_key` | Independent session |
| `ALERT_APPROVED` | Analyst approves held transfer | Reviewer ID | `fraud_alert` | `SUCCESS` | `transaction_id`, `amount`, `decision_note` | Same transaction |
| `ALERT_REJECTED` | Analyst rejects held transfer | Reviewer ID | `fraud_alert` | `SUCCESS` | `transaction_id`, `decision_note` | Same transaction |
| `ALERT_ESCALATED` | Analyst escalates alert with note | Reviewer ID | `fraud_alert` | `SUCCESS` | `transaction_id`, note | Same transaction |
| `ALERT_APPROVE_FAILED_FUNDS` | Sender balance dropped during hold | Reviewer ID | `fraud_alert` | `FAILURE` | `transaction_id`, reason, note | Same transaction |
| `ACCESS_DENIED_SEPARATION_OF_DUTIES` | Reviewer is party to transaction/dispute | Reviewer ID | `fraud_alert` / `dispute` | `DENIED` | `alert_id` / `dispute_id`, reason | Independent session |
| `PAYMENT_INITIATED` | Bill payment initiated | User ID | `payment` | `SUCCESS` | `payment_ref`, `biller_code`, `amount` | Same transaction |
| `PAYMENT_SETTLED` | Bill payment settled by rail | User ID | `payment` | `SUCCESS` | `payment_ref`, `rail_reference` | Same transaction |
| `PAYMENT_FAILED` | Bill payment declined by rail | User ID | `payment` | `FAILURE` | `payment_ref`, reason | Same transaction |
| `PAYMENT_UNKNOWN` | Rail timeout, outcome unknown | User ID | `payment` | `UNKNOWN` | `payment_ref`, reason | Same transaction |
| `PAYMENT_REVERSED` | Failed payment refunded | User ID | `payment` | `SUCCESS` | `payment_ref`, `refund_amount` | Same transaction |
| `PAYMENT_NEEDS_INVESTIGATION` | Discrepancy / late settlement | User ID | `payment` | `FAILURE` | `payment_ref`, reason | Same transaction |
| `RECON_RUN_COMPLETED` | Reconciliation run finished | Admin ID | `reconciliation_run` | `SUCCESS` | `run_id`, payments checked, exceptions found | Same transaction |
| `RECON_EXCEPTION_RAISED` | Exception detected during recon | Admin ID | `reconciliation_exception` | `SUCCESS` | `exception_id`, `type`, references, amounts | Same transaction |
| `RECON_EXCEPTION_RESOLVED` | Exception closed with note | Admin ID | `reconciliation_exception` | `SUCCESS` | `exception_id`, `status`, note | Same transaction |
| `DISPUTE_FILED` | Customer files dispute | Customer ID | `dispute` | `SUCCESS` | `dispute_id`, `case_ref`, `category` | Same transaction |
| `DISPUTE_STATUS_CHANGED` | Dispute status updated | Staff ID | `dispute` | `SUCCESS` | `dispute_id`, from/to status, note | Same transaction |
| `DISPUTE_REFUNDED` | Dispute resolved with refund | Staff ID | `dispute` | `SUCCESS` | `dispute_id`, `amount`, `account_id` | Same transaction |
| `DISPUTE_REJECTED` | Dispute rejected with note | Staff ID | `dispute` | `SUCCESS` | `dispute_id`, note | Same transaction |
| `DISPUTE_ESCALATED` | Overdue dispute escalated by sweep | System/Admin | `dispute` | `SUCCESS` | `dispute_id`, escalation level | Same transaction |

> 🔒 **Sensitive Data Sanitizer**: Passwords, password hashes, JWT tokens, and authorization headers are recursively stripped before storing in `details`.

---

## Phase 6: Fraud Engine Decision Flow

```
Client Request
      |
      v
[1] Idempotency Check ---- duplicate key ---> Log IDEMPOTENT_REPLAY & return cached response
      | new key
      v
[2] Account Validation (sender active, recipient active, not self-transfer)
      |
      v
[3] Transaction Limits
      |-- amount > SINGLE_TRANSFER_LIMIT ---> Log TRANSFER_REJECTED_LIMIT & 400
      +-- daily_total + amount > DAILY_LIMIT ---> Log TRANSFER_REJECTED_LIMIT & 400
      |
      v
[4] Fraud Rule Engine (evaluate 5 rules, sum points, cap at 100)
      |
      |-- Score 0-29 -> LOW
      |     +-- Execute atomically under row locks -> Log TRANSFER_COMPLETED -> status: COMPLETED
      |
      |-- Score 30-59 -> MEDIUM
      |     |-- Execute atomically under row locks -> Log TRANSFER_COMPLETED -> status: COMPLETED
      |     +-- Create FraudAlert (OPEN) for analyst visibility
      |
      +-- Score 60-100 -> HIGH (Hold, Don't Move)
            |-- Transaction saved as status: PENDING_REVIEW (no balance change)
            |-- Create FraudAlert (OPEN)
            +-- Log TRANSFER_HELD
                      |
                      v
              Analyst reviews via /fraud/alerts/{id}
                      |
            +---------+---------+
            v         v         v
         approve    reject   escalate
            |         |         |
       Re-lock     No money  Log ALERT_ESCALATED
       accounts    moves     Status: ESCALATED
       Re-check    Log ALERT_REJECTED
       balance     REJECTED
            |
     balance OK? --No--> Log ALERT_APPROVE_FAILED_FUNDS -> status: FAILED
            |
           Yes
            |
     Execute transfer -> Log ALERT_APPROVED -> status: COMPLETED
```

---

## Fraud Rule Table

| Rule | Trigger Condition | Points | Config Key |
|------|-------------------|--------|------------|
| `LARGE_AMOUNT` | amount >= FRAUD_LARGE_AMOUNT_THRESHOLD | 40 | `FRAUD_LARGE_AMOUNT_THRESHOLD=2000.00` |
| `HIGH_VELOCITY` | More than N transfers from sender in last hour | 35 | `FRAUD_HIGH_VELOCITY_COUNT=3` |
| `NEW_RECIPIENT_LARGE` | First-ever transfer to recipient AND amount >= threshold | 30 | `FRAUD_NEW_RECIPIENT_THRESHOLD=500.00` |
| `NEAR_LIMIT` | amount >= 90% of SINGLE_TRANSFER_LIMIT | 25 | `FRAUD_NEAR_LIMIT_PERCENT=0.90` |
| `NEW_ACCOUNT` | Sender account age < N days | 20 | `FRAUD_NEW_ACCOUNT_DAYS=30` |

---

## Dev Seed Script

```bash
python scripts/seed.py
```

| Role | Email | Password | Account No | Balance |
|------|-------|----------|------------|---------|
| customer | customer1@example.com | Customer1Password! | 1000000001 | $10,000.00 |
| customer | customer2@example.com | Customer2Password! | 1000000002 | $5,000.00 |
| risk_analyst | analyst@example.com | Analyst1Password! | N/A | N/A |
| admin | admin@example.com | Admin1Password! | N/A | N/A |

---

## Complete Endpoint Reference

### 1. Authentication & User Management (Phases 2, 7 & 10)
- **`POST /auth/register`** - Register a new user (audited: `USER_REGISTERED`, mass-assignment forbidden)
- **`POST /auth/login`** - OAuth2 login, returns JWT (audited: `LOGIN_SUCCESS`, `LOGIN_FAILED`, lockout after 5 failures)
- **`GET /auth/me`** - Current user profile
- **`POST /admin/users/{id}/unlock`** - Admin only: unlock locked account and reset failed login attempts (audited: `ACCOUNT_UNLOCKED`)

### 2. Accounts (Phases 3 & 7)
- **`POST /accounts`** - Create checking/savings account (audited: `ACCOUNT_CREATED`)
- **`GET /accounts`** - List own accounts
- **`GET /accounts/{id}`** - Single account (ownership/admin check)
- **`GET /accounts/all`** - Admin only: all platform accounts

### 3. Internal Ledger Transfers (Phases 4-7, Prompt 0)
- **`POST /transactions`** - Initiate internal transfer (requires `Idempotency-Key` header)
  - Limits enforced before scoring
  - LOW/MEDIUM risk -> completes (audited: `TRANSFER_COMPLETED`)
  - HIGH risk -> held (audited: `TRANSFER_HELD`)
  - Duplicate keys -> audited: `IDEMPOTENT_REPLAY`
- **`GET /transactions`** - Own transaction history
- **`GET /transactions/{id}`** - Single transaction
- **`GET /staff/transactions`** - Admin & Risk Analyst: paginated platform-wide transactions with risk scores, risk levels, and multi-field filters (status, risk level, amount range, date range, search by reference)

### 4. Bill Payments & External Rail (Phase 8)
- **`POST /payments`** - Initiate external bill payment via 3-step pattern (`Idempotency-Key` required)
- **`GET /payments`** - List own bill payments
- **`GET /payments/{id}`** - Single bill payment + timeline of lifecycle events
- **`GET /admin/payments`** - Admin: list all system payments (filter by status, biller, stuck)
- **`POST /admin/payments/sweep`** - Admin: run recovery sweep on stuck or timed-out payments
- **`PATCH /rail/billers/{code}/failure-mode`** - Admin: configure biller failure simulation mode (`OK`, `DECLINE`, `TIMEOUT_AFTER_PROCESS`, `TIMEOUT_BEFORE_PROCESS`)

### 5. Reconciliation & Exception Queue (Phase 9 - Part A)
- **`POST /admin/recon/run`** - Admin: run reconciliation against payments and rail_records
- **`GET /admin/recon/exceptions`** - Admin & Risk Analyst: view paginated exceptions (filter by status, type)
- **`GET /admin/recon/exceptions/{id}`** - Admin & Risk Analyst: single exception details
- **`POST /admin/recon/exceptions/{id}/resolve`** - Admin: resolve exception with note (`RESOLVED` or `IGNORED`, changes no balances)

### 6. Customer Disputes & SLA Tracking (Phase 9 - Part B)
- **`POST /disputes`** - Customer: file dispute against own payment or transaction (`Idempotency-Key` required)
- **`GET /disputes`** - Customer: list own disputes with customer-safe timeline events
- **`GET /disputes/{id}`** - Customer: single dispute details (internal notes strictly hidden)
- **`GET /staff/disputes`** - Risk Analyst & Admin: list disputes (filter by status, category, assigned_to, overdue)
- **`POST /staff/disputes/{id}/assign`** - Risk Analyst & Admin: assign dispute to analyst
- **`POST /staff/disputes/{id}/status`** - Risk Analyst & Admin: transition status with note and customer visibility flag
- **`POST /staff/disputes/{id}/resolve-refund`** - Risk Analyst & Admin: approve dispute with single refund credited back to account (atomic, row-locked, unique constraint backstop)
- **`POST /staff/disputes/{id}/resolve-reject`** - Risk Analyst & Admin: reject dispute with explanatory note
- **`POST /admin/disputes/escalation-sweep`** - Admin: trigger SLA escalation sweep for overdue cases

### 7. Fraud Review (Phases 6 & 7 - `risk_analyst`, `admin` only)
- **`GET /fraud/alerts`** - List alerts (filtered, paginated)
- **`GET /fraud/alerts/{id}`** - Full alert details + rule breakdown
- **`POST /fraud/alerts/{id}/approve`** - Approve held transfer (audited: `ALERT_APPROVED` / `ALERT_APPROVE_FAILED_FUNDS`)
- **`POST /fraud/alerts/{id}/reject`** - Reject transfer (audited: `ALERT_REJECTED`)
- **`POST /fraud/alerts/{id}/escalate`** - Escalate with note (audited: `ALERT_ESCALATED`)

### 8. Audit Logs & Verification (Phase 7)
- **`GET /audit/logs`** - Paginated audit logs with multi-field filtering (Admin only)
- **`GET /audit/entity/{entity_type}/{entity_id}`** - Chronological timeline for an entity (oldest first).
  - Admin: all entities (`user`, `account`, `transaction`, `payment`, `fraud_alert`, `dispute`, `reconciliation_run`, `reconciliation_exception`)
  - Risk Analyst: `transaction`, `payment`, `fraud_alert`, `dispute` entities
  - Customer: 403 Forbidden
- **`GET /audit/verify`** - Verify SHA-256 hash chain and detect any database tampering (Admin only)

### 9. Operations & Executive Dashboard (Prompt 0)
- **`GET /admin/overview`** - Admin & Risk Analyst: live aggregated operations metrics:
  - Today and yesterday transaction counts
  - Fraud alerts held for review (`OPEN` or `UNDER_REVIEW`)
  - Open reconciliation exceptions (`OPEN`)
  - Open disputes (`OPEN`) and SLA-breached overdue cases
  - Payments grouped by state machine status (`PROCESSING`, `SETTLED`, `FAILED`, `UNKNOWN`, `REVERSED`, `NEEDS_INVESTIGATION`)
  - 7-day daily volume time series: `[{date, count, total_amount}]`
  - Alert risk level distribution (`low`, `medium`, `high`)

---

## Running Tests

The test suite runs against the local native PostgreSQL 16 test database (`sentinelpay_test`):

```bash
# Full test suite (138 tests passing against PostgreSQL native service)
python -m pytest tests/ -v

# Security hardening & production readiness tests (Phase 10 - 33 tests)
python -m pytest tests/test_security.py -v

# Resolution layer tests (Phase 9 - 20 tests)
python -m pytest tests/test_recon.py -v
python -m pytest tests/test_disputes.py -v

# Payment rail and state machine tests (Phase 8 - 31 tests)
python -m pytest tests/test_payments.py -v
python -m pytest tests/test_state_machine.py -v

# Tamper-evident audit log tests (Phase 7 - 10 tests)
python -m pytest tests/test_audit.py -v

# Fraud rules and review integration tests (Phase 6 - 15 tests)
python -m pytest tests/test_fraud_rules.py -v
python -m pytest tests/test_fraud_integration.py -v
```

### Test Suite Breakdown (143 tests, 100% passing)

| Test Module | Tests | Focus Area |
|---|---|---|
| `tests/test_security.py` | 33 | Lockout, rate limiting, password policy, mass assignment, money validation, headers, token security, auth sweep |
| `tests/test_state_machine.py` | 21 | Payment transition matrix: 9 allowed transitions + 12 illegal/terminal transition rejections |
| `tests/test_disputes.py` | 12 | Customer dispute lifecycle, category SLAs, auto-linking to recon exceptions, single-refund idempotency |
| `tests/test_transactions.py` | 11 | Balance deductions, row locking, transfer limits, idempotency replay, balance sufficiency |
| `tests/test_payments.py` | 10 | 3-step payment flow, biller timeouts, crash recovery sweep, customer isolation, late-settled edge cases |
| `tests/test_audit.py` | 10 | SHA-256 hash chaining, DB trigger tamper prevention, verification endpoint, sensitive data sanitization |
| `tests/test_fraud_integration.py` | 9 | Analyst hold/review/approve/reject/escalate flows, self-review block, concurrent balance depletion |
| `tests/test_recon.py` | 8 | Read-only reconciliation, 5 exception types, in-flight payment exclusion, duplicate recon idempotency |
| `tests/test_accounts.py` | 7 | Checking/savings account creation, ownership isolation, account lookup |
| `tests/test_auth.py` | 7 | User registration, password hashing, JWT token issuance, role-based claims |
| `tests/test_fraud_rules.py` | 6 | Rule boundary thresholds: large amount, velocity, new recipient, near limit, new account |
| `tests/test_staff_ui.py` | 5 | UI prep: Admin overview metrics/aggregations, paginated staff transaction filters & risk tags |
| `tests/test_concurrency.py` | 2 | Concurrent transfers & double-spend prevention under simultaneous requests |
| `tests/test_health.py` | 2 | Health check endpoint and DB ping verification |
| **Total** | **143** | **Zero failures, native PostgreSQL transactional isolation** |

---

## Tech Stack

- **Python 3.14** / **FastAPI** - web framework
- **PostgreSQL 16** - primary relational database (native Windows service)
- **SQLAlchemy 2.0** - ORM with row locking (`with_for_update`), advisory locks (`pg_advisory_xact_lock`), and partial indexes
- **Alembic** - schema migrations with PostgreSQL plpgsql triggers
- **bcrypt** - password hashing (direct)
- **PyJWT** - JWT authentication
- **Pydantic v2** - validation and settings
- **pytest** - automated test suite (143 tests passing)
