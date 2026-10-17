"""
SentinelPay – Reconciliation Service (Phase 9 - Part A).

Read-only analysis comparing SentinelPay's internal ledger (payments)
against the external rail's ledger (rail_records).

=============================================================================
CRITICAL ARCHITECTURAL GUARANTEE:
Reconciliation is strictly an OBSERVATIONAL and AUDITING engine.
It NEVER modifies account balances or payment statuses directly.
Moving money or mutating payment states automatically based on external
reconciliation discrepancies risks compounding ledger divergence or
creating duplicate credits/refunds without human review.
All exceptions must be investigated and resolved by authorized personnel.
=============================================================================
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record_event
from app.auth.models import User
from app.core.config import settings
from app.payments.models import Payment, PaymentStatus
from app.rail.models import RailRecord, RailRecordStatus
from app.recon.models import (
    ExceptionStatus,
    ExceptionType,
    ReconciliationException,
    ReconciliationRun,
)
from app.recon.schemas import ResolveExceptionRequest


def run_reconciliation(
    db: Session,
    admin_user: User,
    ip_address: str | None = None,
) -> ReconciliationRun:
    """Execute a batch reconciliation run comparing payments and rail_records.

    Detects:
      - MISSING_AT_BILLER: Local is SETTLED, rail has no record or FAILED record.
      - ORPHAN_RAIL_RECORD: Rail has SETTLED record, no local payment exists.
      - STATUS_MISMATCH: Local is FAILED/REVERSED, rail is SETTLED (money loss).
      - AMOUNT_MISMATCH: Same reference, different amounts.
      - SUSPECTED_DUPLICATE: Same user, biller, amount within window.

    Skips in-flight payments in PROCESSING or UNKNOWN younger than
    PAYMENT_STUCK_AFTER_SECONDS threshold.
    """
    now_utc = datetime.now(timezone.utc)
    stuck_seconds = getattr(settings, "PAYMENT_STUCK_AFTER_SECONDS", 120)
    duplicate_window_sec = getattr(settings, "RECON_DUPLICATE_WINDOW_SECONDS", 300)
    inflight_cutoff = now_utc - timedelta(seconds=stuck_seconds)

    # 1. Initialize Run record
    run = ReconciliationRun(
        started_at=now_utc,
        started_by=admin_user.id,
    )
    db.add(run)
    db.flush()

    # 2. Fetch all records
    payments = list(db.scalars(select(Payment).order_by(Payment.id)).all())
    rail_records = list(db.scalars(select(RailRecord).order_by(RailRecord.id)).all())

    rail_by_ref: dict[str, RailRecord] = {r.rail_reference: r for r in rail_records}
    payment_by_ref: dict[str, Payment] = {p.rail_reference: p for p in payments}

    # Filter out in-flight payments (young PROCESSING / UNKNOWN)
    eligible_payments: list[Payment] = []
    for p in payments:
        if p.status in [PaymentStatus.PROCESSING, PaymentStatus.UNKNOWN]:
            # If created or updated recently, it's still in-flight
            ts = p.updated_at or p.created_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= inflight_cutoff:
                continue
        eligible_payments.append(p)

    payments_checked = len(eligible_payments)
    rail_records_checked = len(rail_records)

    total_found = 0
    total_new = 0

    def _add_exception(
        etype: ExceptionType,
        payment_id: int | None,
        rail_ref: str | None,
        local_st: str | None,
        rail_st: str | None,
        local_amt: Decimal | None,
        rail_amt: Decimal | None,
        details_dict: dict | None,
    ) -> None:
        nonlocal total_found, total_new

        # Check if an OPEN exception for this (type, payment_id, rail_ref) already exists
        stmt = select(ReconciliationException).where(
            ReconciliationException.exception_type == etype,
            ReconciliationException.payment_id == payment_id,
            ReconciliationException.rail_reference == rail_ref,
            ReconciliationException.status == ExceptionStatus.OPEN,
        )
        existing = db.scalar(stmt)
        if existing:
            total_found += 1
            return

        # Insert new exception
        exc = ReconciliationException(
            run_id=run.id,
            exception_type=etype,
            payment_id=payment_id,
            rail_reference=rail_ref,
            local_status=local_st,
            rail_status=rail_st,
            local_amount=local_amt,
            rail_amount=rail_amt,
            status=ExceptionStatus.OPEN,
            details=details_dict,
            created_at=now_utc,
        )
        db.add(exc)
        db.flush()

        total_found += 1
        total_new += 1

        record_event(
            db=db,
            event_type="RECON_EXCEPTION_RAISED",
            actor_user_id=admin_user.id,
            actor_role=admin_user.role.value,
            entity_type="reconciliation_exception",
            entity_id=str(exc.id),
            outcome="SUCCESS",
            details={
                "exception_type": etype.value,
                "payment_id": payment_id,
                "rail_reference": rail_ref,
            },
            ip_address=ip_address,
        )

    # 3. Check eligible payments against rail records
    for p in eligible_payments:
        r = rail_by_ref.get(p.rail_reference)

        # A) MISSING_AT_BILLER: Local SETTLED, rail missing or FAILED
        if p.status == PaymentStatus.SETTLED:
            if r is None:
                _add_exception(
                    ExceptionType.MISSING_AT_BILLER,
                    p.id,
                    p.rail_reference,
                    p.status.value,
                    None,
                    p.amount,
                    None,
                    {"reason": "Payment is SETTLED locally but rail has no record"},
                )
            elif r.status == RailRecordStatus.FAILED:
                _add_exception(
                    ExceptionType.MISSING_AT_BILLER,
                    p.id,
                    p.rail_reference,
                    p.status.value,
                    r.status.value,
                    p.amount,
                    r.amount,
                    {"reason": "Payment is SETTLED locally but rail recorded FAILED"},
                )

        # B) STATUS_MISMATCH: Local is FAILED/REVERSED, rail is SETTLED (money loss)
        if p.status in [PaymentStatus.FAILED, PaymentStatus.REVERSED]:
            if r is not None and r.status == RailRecordStatus.SETTLED:
                _add_exception(
                    ExceptionType.STATUS_MISMATCH,
                    p.id,
                    p.rail_reference,
                    p.status.value,
                    r.status.value,
                    p.amount,
                    r.amount,
                    {"reason": "Payment is FAILED/REVERSED locally but rail recorded SETTLED"},
                )

        # C) AMOUNT_MISMATCH: Same reference, different amounts
        if r is not None and p.amount != r.amount:
            _add_exception(
                ExceptionType.AMOUNT_MISMATCH,
                p.id,
                p.rail_reference,
                p.status.value,
                r.status.value,
                p.amount,
                r.amount,
                {
                    "local_amount": str(p.amount),
                    "rail_amount": str(r.amount),
                    "discrepancy": str(abs(p.amount - r.amount)),
                },
            )

    # 4. Check rail records for ORPHANS
    for r in rail_records:
        if r.status == RailRecordStatus.SETTLED and r.rail_reference not in payment_by_ref:
            _add_exception(
                ExceptionType.ORPHAN_RAIL_RECORD,
                None,
                r.rail_reference,
                None,
                r.status.value,
                None,
                r.amount,
                {"reason": "Rail record is SETTLED but no matching local payment exists"},
            )

    # 5. Check for SUSPECTED_DUPLICATE among eligible payments
    # Same user, biller, amount created within RECON_DUPLICATE_WINDOW_SECONDS
    for i in range(len(eligible_payments)):
        p1 = eligible_payments[i]
        t1 = p1.created_at.replace(tzinfo=timezone.utc) if p1.created_at.tzinfo is None else p1.created_at
        for j in range(i + 1, len(eligible_payments)):
            p2 = eligible_payments[j]
            if (
                p1.user_id == p2.user_id
                and p1.biller_code == p2.biller_code
                and p1.amount == p2.amount
                and p1.rail_reference != p2.rail_reference
            ):
                t2 = p2.created_at.replace(tzinfo=timezone.utc) if p2.created_at.tzinfo is None else p2.created_at
                delta = abs((t2 - t1).total_seconds())
                if delta <= duplicate_window_sec:
                    _add_exception(
                        ExceptionType.SUSPECTED_DUPLICATE,
                        p2.id,
                        p2.rail_reference,
                        p2.status.value,
                        rail_by_ref.get(p2.rail_reference).status.value if rail_by_ref.get(p2.rail_reference) else None,
                        p2.amount,
                        rail_by_ref.get(p2.rail_reference).amount if rail_by_ref.get(p2.rail_reference) else None,
                        {
                            "suspected_duplicate_of_payment_id": p1.id,
                            "suspected_duplicate_payment_ref": p1.payment_ref,
                            "time_difference_seconds": delta,
                            "status_note": "Flagged as suspected duplicate, not proven.",
                        },
                    )

    # 6. Finalize Run summary
    run.finished_at = datetime.now(timezone.utc)
    run.payments_checked = payments_checked
    run.rail_records_checked = rail_records_checked
    run.exceptions_found = total_found
    run.exceptions_new = total_new
    db.flush()

    record_event(
        db=db,
        event_type="RECON_RUN_COMPLETED",
        actor_user_id=admin_user.id,
        actor_role=admin_user.role.value,
        entity_type="reconciliation_run",
        entity_id=str(run.id),
        outcome="SUCCESS",
        details={
            "payments_checked": payments_checked,
            "rail_records_checked": rail_records_checked,
            "exceptions_found": total_found,
            "exceptions_new": total_new,
        },
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(run)
    return run


def resolve_reconciliation_exception(
    db: Session,
    exception_id: int,
    admin_user: User,
    payload: ResolveExceptionRequest,
    ip_address: str | None = None,
) -> ReconciliationException:
    """Resolve or ignore a single reconciliation exception.

    Locks row with with_for_update().
    Returns 409 if already resolved or closed.
    CHANGES NO BALANCES OR PAYMENT STATUSES.
    """
    exc = db.scalar(
        select(ReconciliationException)
        .where(ReconciliationException.id == exception_id)
        .with_for_update()
    )
    if not exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reconciliation exception {exception_id} not found",
        )

    if exc.status != ExceptionStatus.OPEN:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Exception is already {exc.status.value}",
        )

    now_utc = datetime.now(timezone.utc)
    exc.status = payload.status
    exc.resolved_by = admin_user.id
    exc.resolved_at = now_utc
    exc.resolution_note = payload.resolution_note

    record_event(
        db=db,
        event_type="RECON_EXCEPTION_RESOLVED",
        actor_user_id=admin_user.id,
        actor_role=admin_user.role.value,
        entity_type="reconciliation_exception",
        entity_id=str(exc.id),
        outcome="SUCCESS",
        details={
            "new_status": exc.status.value,
            "resolution_note": payload.resolution_note,
        },
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(exc)
    return exc
