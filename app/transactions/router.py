"""
SentinelPay – Router endpoints for money transfers and transaction history.
"""

from datetime import datetime, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.accounts.models import Account
from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import check_rate_limit
from app.fraud.models import RiskLevel
from app.transactions.models import Transaction, TransactionStatus
from app.transactions.schemas import (
    PaginatedStaffTransactions,
    StaffTransactionResponse,
    TransactionCreate,
    TransactionResponse,
)
from app.transactions.service import execute_transfer

router = APIRouter(prefix="/transactions", tags=["Transactions"])
staff_router = APIRouter(prefix="/staff/transactions", tags=["Staff Transactions"])


@router.post(
    "",
    response_model=TransactionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate a money transfer between accounts",
)
def create_transaction(
    payload: TransactionCreate,
    request: Request,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Execute an atomic transfer from the current user's account to a recipient account.
    Requires an 'Idempotency-Key' request header.
    """
    if not idempotency_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Idempotency-Key header",
        )

    # Per-user rate limiting on transactions
    check_rate_limit(
        request=request,
        endpoint_key="transactions",
        key_type="user",
        user_id=current_user.id,
        max_requests=settings.RATE_LIMIT_TRANSACTION_MAX,
        window_seconds=settings.RATE_LIMIT_TRANSACTION_WINDOW_SECONDS,
        db=db,
    )

    ip_address = request.client.host if request.client else None
    return execute_transfer(db, current_user, payload, idempotency_key, ip_address=ip_address)



@router.get(
    "",
    response_model=list[TransactionResponse],
    summary="List transaction history for current user",
)
def list_my_transactions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Transaction]:
    """
    Retrieve all transactions (both sent and received) involving any account owned by the current user.
    """
    # Fetch all account IDs owned by current user
    user_account_ids_stmt = select(Account.id).where(Account.user_id == current_user.id)
    user_account_ids = db.scalars(user_account_ids_stmt).all()

    if not user_account_ids:
        return []

    stmt = (
        select(Transaction)
        .where(
            or_(
                Transaction.sender_account_id.in_(user_account_ids),
                Transaction.recipient_account_id.in_(user_account_ids),
            )
        )
        .order_by(Transaction.created_at.desc())
    )
    transactions = db.scalars(stmt).all()
    return list(transactions)


@router.get(
    "/{transaction_id}",
    response_model=TransactionResponse,
    summary="Get single transaction details with ownership authorization",
)
def get_transaction_by_id(
    transaction_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Transaction:
    """
    Retrieve details for a single transaction by ID.
    Ownership check: Permitted ONLY if the current user owns either the sender account
    or recipient account, OR if current user holds role ADMIN / RISK_ANALYST.
    """
    transaction = db.get(Transaction, transaction_id)
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found",
        )

    # Fetch sender and recipient accounts to verify ownership
    sender_account = db.get(Account, transaction.sender_account_id)
    recipient_account = db.get(Account, transaction.recipient_account_id)

    is_sender_owner = sender_account and sender_account.user_id == current_user.id
    is_recipient_owner = recipient_account and recipient_account.user_id == current_user.id
    is_privileged = current_user.role in [UserRole.ADMIN, UserRole.RISK_ANALYST]

    if not (is_sender_owner or is_recipient_owner or is_privileged):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You are not a party to this transaction",
        )

    return transaction


# ─────────────────────────────────────────────────────────────
# STAFF TRANSACTIONS ENDPOINT
# ─────────────────────────────────────────────────────────────

@staff_router.get(
    "",
    response_model=PaginatedStaffTransactions,
    summary="List transactions with filters and risk indicators (Admin, Risk Analyst)",
)
def list_staff_transactions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status_filter: TransactionStatus | None = Query(None, alias="status"),
    risk_level_filter: RiskLevel | None = Query(None, alias="risk_level"),
    min_amount: Decimal | None = Query(None, ge=0),
    max_amount: Decimal | None = Query(None, ge=0),
    from_date: datetime | None = Query(None),
    start_date: datetime | None = Query(None),
    to_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    transaction_ref: str | None = Query(None),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.RISK_ANALYST)),
    db: Session = Depends(get_db),
) -> PaginatedStaffTransactions:
    """
    Paginated list of transactions across all accounts for operations and fraud review.
    Includes risk_score and risk_level. Customers receive 403 Forbidden.
    """
    stmt = select(Transaction)

    if status_filter:
        stmt = stmt.where(Transaction.status == status_filter)
    if risk_level_filter:
        stmt = stmt.where(Transaction.risk_level == risk_level_filter)
    if min_amount is not None:
        stmt = stmt.where(Transaction.amount >= min_amount)
    if max_amount is not None:
        stmt = stmt.where(Transaction.amount <= max_amount)

    effective_start = from_date or start_date
    if effective_start is not None:
        if effective_start.tzinfo is None:
            effective_start = effective_start.replace(tzinfo=timezone.utc)
        stmt = stmt.where(Transaction.created_at >= effective_start)

    effective_end = to_date or end_date
    if effective_end is not None:
        if effective_end.tzinfo is None:
            effective_end = effective_end.replace(tzinfo=timezone.utc)
        stmt = stmt.where(Transaction.created_at <= effective_end)

    if transaction_ref:
        stmt = stmt.where(Transaction.transaction_ref.ilike(f"%{transaction_ref.strip()}%"))

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    stmt = (
        stmt.order_by(Transaction.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())

    return PaginatedStaffTransactions(
        items=[
            StaffTransactionResponse(
                id=tx.id,
                transaction_ref=tx.transaction_ref,
                sender_account_id=tx.sender_account_id,
                recipient_account_id=tx.recipient_account_id,
                amount=tx.amount,
                status=tx.status,
                description=tx.description,
                risk_score=tx.risk_score,
                risk_level=tx.risk_level.value if hasattr(tx.risk_level, "value") else (str(tx.risk_level) if tx.risk_level else None),
                created_at=tx.created_at,
                completed_at=tx.completed_at,
            )
            for tx in items
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )
