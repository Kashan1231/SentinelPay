"""
SentinelPay – Audit module (Phase 7).
Append-only immutable audit log and tamper-evident hash chain.
"""

from app.audit.models import AuditEventType, AuditLog, AuditOutcome
from app.audit.service import (
    record_event,
    record_event_independent,
    verify_hash_chain,
)

__all__ = [
    "AuditLog",
    "AuditEventType",
    "AuditOutcome",
    "record_event",
    "record_event_independent",
    "verify_hash_chain",
]
