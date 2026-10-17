"""
SentinelPay – Router endpoints for bank account management and ownership checks.
"""

import random
import string
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.accounts.schemas import AccountCreate, AccountResponse
from app.audit.service import record_event
from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.database import get_db

router = APIRouter(prefix="/accounts", tags=["Accounts"])


def generate_account_number(db: Session) -> str:
    """Generate a unique 10-digit numeric string for an account number."""
    while True:
        acc_num = "".join(random.choices(string.digits, k=10))
        stmt = select(Account).where(Account.account_number == acc_num)
        if db.scalar(stmt) is None:
            return acc_num


@router.post(
    "",
    response_model=AccountResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new bank account for the current user",
)
def create_account(
    account_in: AccountCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Account:
    """
    Create a new account for the authenticated user starting with a 0.00 balance.
    Account number is randomly generated and guaranteed unique.
    """
    account_number = generate_account_number(db)

    account = Account(
        user_id=current_user.id,
        account_number=account_number,
        account_type=account_in.account_type,
        balance=Decimal("0.00"),
    )
    db.add(account)
    db.flush()

    ip_address = request.client.host if request.client else None
    record_event(
        db=db,
        event_type="ACCOUNT_CREATED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="account",
        entity_id=str(account.id),
        outcome="SUCCESS",
        details={
            "account_number": account.account_number,
            "account_type": account.account_type.value,
            "initial_balance": str(account.balance),
        },
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(account)

    return account


@router.get(
    "",
    response_model=list[AccountResponse],
    summary="List current user's accounts",
)
def list_my_accounts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Account]:
    """
    Retrieve only bank accounts belonging to the authenticated user.
    """
    stmt = select(Account).where(Account.user_id == current_user.id).order_by(Account.created_at.desc())
    accounts = db.scalars(stmt).all()
    return list(accounts)


@router.get(
    "/all",
    response_model=list[AccountResponse],
    summary="List all accounts system-wide (Admin only)",
)
def list_all_accounts(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[Account]:
    """
    Retrieve all accounts across the entire platform. Restricted to ADMIN role.
    """
    stmt = select(Account).order_by(Account.created_at.desc())
    accounts = db.scalars(stmt).all()
    return list(accounts)


@router.get(
    "/{account_id}",
    response_model=AccountResponse,
    summary="Get single account details with resource ownership verification",
)
def get_account_by_id(
    account_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Account:
    """
    Retrieve details for a single account by ID.
    Ownership check: Permitted ONLY if account belongs to current user
    OR current user holds role ADMIN / RISK_ANALYST.
    """
    account = db.get(Account, account_id)
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    # Ownership check: Customer cannot view another customer's account
    if (
        account.user_id != current_user.id
        and current_user.role not in [UserRole.ADMIN, UserRole.RISK_ANALYST]
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not own this account",
        )

    return account
