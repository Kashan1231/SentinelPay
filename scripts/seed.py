"""
=============================================================================
SENTINELPAY — DEVELOPMENT SEED SCRIPT (DEV-ONLY)
=============================================================================
WARNING: This script is intended strictly for local development, demoing,
and exploratory testing in Swagger/OpenAPI. NEVER execute against production!

Creates demo personas:
  - 2 Customers (funded checking accounts for transfer simulation)
  - 1 Risk Analyst (for reviewing, approving, rejecting, escalating alerts)
  - 1 Administrator (full system privileges)

All account balances are funded directly at database seed time.
Balance is NEVER editable via any API endpoint.
=============================================================================
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import select

from app.accounts.models import Account, AccountStatus, AccountType
from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.core.database import SessionLocal
from app.rail.models import FailureMode, RailBiller


DEMO_USERS = [
    {
        "email": "customer1@example.com",
        "full_name": "Alice Customer",
        "password": "Customer1Password!",
        "role": UserRole.CUSTOMER,
        "account_number": "1000000001",
        "initial_balance": Decimal("10000.00"),
        "account_age_days": 60,  # Established account (> 30 days)
    },
    {
        "email": "customer2@example.com",
        "full_name": "Bob Customer",
        "password": "Customer2Password!",
        "role": UserRole.CUSTOMER,
        "account_number": "1000000002",
        "initial_balance": Decimal("5000.00"),
        "account_age_days": 60,  # Established account (> 30 days)
    },
    {
        "email": "analyst@example.com",
        "full_name": "Rachel Analyst",
        "password": "Analyst1Password!",
        "role": UserRole.RISK_ANALYST,
        "account_number": None,
        "initial_balance": None,
        "account_age_days": 60,
    },
    {
        "email": "admin@example.com",
        "full_name": "Adam Administrator",
        "password": "Admin1Password!",
        "role": UserRole.ADMIN,
        "account_number": None,
        "initial_balance": None,
        "account_age_days": 60,
    },
]

DEMO_BILLERS = [
    {"code": "ELECTRIC_CO", "name": "Electric Company", "failure_mode": FailureMode.OK},
    {"code": "GAS_CORP", "name": "Gas Corporation", "failure_mode": FailureMode.DECLINE},
    {"code": "WATER_UTIL", "name": "Water Utility", "failure_mode": FailureMode.TIMEOUT_AFTER_PROCESS},
    {"code": "TELECOM_INC", "name": "Telecom Inc.", "failure_mode": FailureMode.TIMEOUT_BEFORE_PROCESS},
]


def seed_database() -> None:
    """Populate database with demo accounts, billers, and print credentials to console."""
    db = SessionLocal()
    now = datetime.now(timezone.utc)

    print("\n" + "=" * 78)
    print("  SENTINELPAY DEVELOPMENT SEED SCRIPT (DEV-ONLY)")
    print("=" * 78)

    try:
        results = []

        for item in DEMO_USERS:
            # 1. Upsert User
            stmt = select(User).where(User.email == item["email"])
            user = db.scalar(stmt)
            if not user:
                user = User(
                    email=item["email"],
                    full_name=item["full_name"],
                    hashed_password=hash_password(item["password"]),
                    role=item["role"],
                    is_active=True,
                    created_at=now - timedelta(days=item["account_age_days"]),
                )
                db.add(user)
                db.flush()
            else:
                user.hashed_password = hash_password(item["password"])
                user.role = item["role"]
                user.full_name = item["full_name"]
                db.flush()

            account_info = "N/A"
            balance_info = "N/A"

            # 2. Upsert Account if applicable
            if item["account_number"]:
                acc_stmt = select(Account).where(Account.account_number == item["account_number"])
                account = db.scalar(acc_stmt)
                if not account:
                    account = Account(
                        user_id=user.id,
                        account_number=item["account_number"],
                        account_type=AccountType.CHECKING,
                        balance=item["initial_balance"],
                        status=AccountStatus.ACTIVE,
                        created_at=now - timedelta(days=item["account_age_days"]),
                    )
                    db.add(account)
                    db.flush()
                else:
                    account.balance = item["initial_balance"]
                    account.status = AccountStatus.ACTIVE
                    db.flush()

                account_info = account.account_number
                balance_info = f"${account.balance:,.2f}"

            results.append({
                "Role": item["role"].value,
                "Email": item["email"],
                "Password": item["password"],
                "Account": account_info,
                "Balance": balance_info,
            })

        # 3. Seed billers (Phase 8)
        print("\n  Seeding mock billers...")
        for biller_data in DEMO_BILLERS:
            existing = db.scalar(
                select(RailBiller).where(RailBiller.code == biller_data["code"])
            )
            if not existing:
                biller = RailBiller(
                    code=biller_data["code"],
                    name=biller_data["name"],
                    failure_mode=biller_data["failure_mode"],
                    is_active=True,
                )
                db.add(biller)
            else:
                existing.failure_mode = biller_data["failure_mode"]
                existing.name = biller_data["name"]
                existing.is_active = True

        db.commit()

        # Display summary table
        print(f"{'Role':<14} | {'Email':<24} | {'Password':<20} | {'Account No':<12} | {'Balance':<10}")
        print("-" * 90)
        for r in results:
            print(f"{r['Role']:<14} | {r['Email']:<24} | {r['Password']:<20} | {r['Account']:<12} | {r['Balance']:<10}")
        print("=" * 90)

        print(f"\n{'Biller Code':<18} | {'Name':<20} | {'Failure Mode':<25}")
        print("-" * 70)
        for b in DEMO_BILLERS:
            print(f"{b['code']:<18} | {b['name']:<20} | {b['failure_mode'].value:<25}")
        print("=" * 70)
        print("Seed completed successfully! You can now authenticate via /auth/login\n")

    except Exception as e:
        db.rollback()
        print(f"Error during seeding: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()

