"""
SentinelPay – Standalone CLI Script for Dispute Escalation Sweep (Phase 9 - Part B).
"""

from app.core.database import SessionLocal
from app.disputes.service import sweep_escalate_overdue_disputes


def main() -> None:
    print("=" * 60)
    print("SENTINELPAY — DISPUTE SLA ESCALATION SWEEP")
    print("=" * 60)

    db = SessionLocal()
    try:
        results = sweep_escalate_overdue_disputes(db, ip_address="127.0.0.1 (CLI)")
        print(f"Overdue disputes found: {results['overdue_found']}")
        print(f"Disputes escalated:     {results['escalated']}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
