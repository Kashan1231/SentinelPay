"""
SentinelPay – Audit service layer.
Part of Phase 7: Append-only immutable audit trail and tamper-evident hash chain.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.core.database import SessionLocal, engine

# 64-bit integer identifier for PostgreSQL transaction-level advisory lock.
# Fits inside PostgreSQL signed 64-bit integer (bigint).
AUDIT_CHAIN_LOCK_ID = 884848484848

SENSITIVE_KEYS = {
    "password",
    "hashed_password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "secret",
}


def sanitize_details(details: dict[str, Any] | None) -> dict[str, Any]:
    """
    Sanitize audit details payload to ensure sensitive credentials, tokens,
    or authorization headers are never logged to the immutable ledger.
    """
    if not details:
        return {}
    cleaned: dict[str, Any] = {}
    for k, v in details.items():
        key_lower = str(k).lower()
        if any(s in key_lower for s in SENSITIVE_KEYS):
            continue  # Strip sensitive key
        if isinstance(v, dict):
            cleaned[k] = sanitize_details(v)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitize_details(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


def compute_canonical_payload(
    prev_hash: str | None,
    event_type: str,
    actor_user_id: int | None,
    actor_role: str | None,
    entity_type: str | None,
    entity_id: str | None,
    outcome: str,
    details: dict[str, Any] | None,
    ip_address: str | None,
    created_at: datetime,
) -> str:
    """
    Generate a canonical, deterministic JSON string representation of the audit row fields.
    Sorts dictionary keys and uses compact separators to eliminate serialization ambiguity.
    """
    # Normalize timestamp to UTC ISO 8601 string
    ts = created_at.astimezone(timezone.utc).isoformat()
    canonical_dict = {
        "prev_hash": prev_hash or "",
        "event_type": event_type,
        "actor_user_id": str(actor_user_id) if actor_user_id is not None else "",
        "actor_role": actor_role or "",
        "entity_type": entity_type or "",
        "entity_id": entity_id or "",
        "outcome": outcome,
        "details": details or {},
        "ip_address": ip_address or "",
        "created_at": ts,
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))


def compute_row_hash(
    prev_hash: str | None,
    event_type: str,
    actor_user_id: int | None,
    actor_role: str | None,
    entity_type: str | None,
    entity_id: str | None,
    outcome: str,
    details: dict[str, Any] | None,
    ip_address: str | None,
    created_at: datetime,
) -> str:
    """Compute SHA-256 hash of canonical audit row payload including previous row hash."""
    payload_str = compute_canonical_payload(
        prev_hash=prev_hash,
        event_type=event_type,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        entity_type=entity_type,
        entity_id=entity_id,
        outcome=outcome,
        details=details,
        ip_address=ip_address,
        created_at=created_at,
    )
    return hashlib.sha256(payload_str.encode("utf-8")).hexdigest()


def record_event(
    db: Session,
    event_type: str,
    actor_user_id: int | None = None,
    actor_role: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    outcome: str = "SUCCESS",
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """
    Record an audit log event within the CALLER's active database transaction.
    Does NOT call db.commit() — it commits or rolls back atomically alongside caller's work.

    CONCURRENCY & HASH-CHAIN SAFETY:
    Acquires a transaction-level PostgreSQL advisory lock (pg_advisory_xact_lock) before reading
    the latest row_hash.
    WHY NEEDED:
    Under concurrent writes, multiple simultaneous transactions could otherwise read the same
    latest row_hash as their prev_hash. This would fork/branch the hash chain and break the linear
    cryptographic verification. The advisory lock serializes access to the chain tail until the
    transaction commits or rolls back, without deadlocking table row locks.
    """
    sanitized = sanitize_details(details)

    # 1. Acquire transaction-level advisory lock to serialize hash-chain tail access
    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": AUDIT_CHAIN_LOCK_ID},
    )

    # 2. Query previous row's hash
    stmt_last = select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
    prev_hash = db.scalar(stmt_last)

    # 3. Timestamp and compute deterministic row hash
    now_utc = datetime.now(timezone.utc)
    row_hash = compute_row_hash(
        prev_hash=prev_hash,
        event_type=event_type,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        entity_type=entity_type,
        entity_id=entity_id,
        outcome=outcome,
        details=sanitized,
        ip_address=ip_address,
        created_at=now_utc,
    )

    # 4. Insert row into active transaction (caller commits)
    log_entry = AuditLog(
        event_type=event_type,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        entity_type=entity_type,
        entity_id=entity_id,
        outcome=outcome,
        details=sanitized,
        ip_address=ip_address,
        prev_hash=prev_hash,
        row_hash=row_hash,
        created_at=now_utc,
    )
    db.add(log_entry)
    db.flush()
    return log_entry


def record_event_independent(
    event_type: str,
    actor_user_id: int | None = None,
    actor_role: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    outcome: str = "FAILURE",
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    db: Session | None = None,
) -> AuditLog:
    """
    Record an audit log event in an INDEPENDENT transaction session and commit immediately.
    Used strictly for security rejections, authentication failures, and access denials where
    the audit event MUST persist even if the main operation is aborted/rolled back.
    """
    bind = db.get_bind() if db is not None else engine
    session = Session(bind=bind, autocommit=False, autoflush=False)
    try:
        log_entry = record_event(
            db=session,
            event_type=event_type,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            entity_type=entity_type,
            entity_id=entity_id,
            outcome=outcome,
            details=details,
            ip_address=ip_address,
        )
        session.commit()
        session.refresh(log_entry)
        return log_entry
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def verify_hash_chain(db: Session) -> dict[str, Any]:
    """
    Walk the entire audit log chain sequentially and verify:
    1. Each row's prev_hash matches the previous row's row_hash (genesis row prev_hash is None).
    2. Each row's row_hash matches the SHA-256 hash recomputed from its stored canonical fields.

    Returns:
    {
        "valid": True/False,
        "checked": N,
        "first_broken_id": None or broken_row_id
    }
    """
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    rows = list(db.scalars(stmt).all())

    checked = 0
    prev_expected_hash: str | None = None

    for row in rows:
        # Check chain link
        if row.prev_hash != prev_expected_hash:
            return {
                "valid": False,
                "checked": checked,
                "first_broken_id": row.id,
            }

        # Check payload integrity
        expected_hash = compute_row_hash(
            prev_hash=row.prev_hash,
            event_type=row.event_type,
            actor_user_id=row.actor_user_id,
            actor_role=row.actor_role,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            outcome=row.outcome,
            details=row.details,
            ip_address=row.ip_address,
            created_at=row.created_at,
        )

        if row.row_hash != expected_hash:
            return {
                "valid": False,
                "checked": checked,
                "first_broken_id": row.id,
            }

        prev_expected_hash = row.row_hash
        checked += 1

    return {
        "valid": True,
        "checked": checked,
        "first_broken_id": None,
    }
