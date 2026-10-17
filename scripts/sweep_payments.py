"""
=============================================================================
SENTINELPAY — PAYMENT SWEEP SCRIPT (Phase 8)
=============================================================================
Finds payments stuck in PROCESSING or UNKNOWN longer than the configured
threshold and resolves them via rail status inquiry.

Run manually:
  python scripts/sweep_payments.py

Or via the admin API:
  POST /admin/payments/sweep
=============================================================================
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.database import SessionLocal
from app.payments.recovery import sweep_stuck_payments


def main() -> None:
    print("\n" + "=" * 60)
    print("  SENTINELPAY PAYMENT SWEEP")
    print("=" * 60)

    db = SessionLocal()
    try:
        result = sweep_stuck_payments(db)
        print(f"\n  Found:    {result['found']} stuck payment(s)")
        print(f"  Resolved: {result['resolved']}")
        print(f"  Errors:   {result['errors']}")
        print("=" * 60 + "\n")
    except Exception as e:
        print(f"Error during sweep: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
