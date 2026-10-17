"""
SentinelPay – Mock rail client (Phase 8).

RailClient is an interface: one concrete implementation (MockRailClient) calls
the rail module in-process.  This design allows swapping for a real HTTP client
later without changing the payment service.

IDEMPOTENCY:  The rail deduplicates by rail_reference.  Resubmitting the same
reference never creates a second record.  This mirrors how real payment rails
(e.g. Visa Direct, RAAST) handle sender-provided reference identifiers.
"""

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.rail.models import (
    FailureMode,
    RailBiller,
    RailRecord,
    RailRecordStatus,
)


class RailStatus(str, Enum):
    """Status values returned by the rail's status inquiry."""

    SETTLED = "SETTLED"
    FAILED = "FAILED"
    NOT_FOUND = "NOT_FOUND"


class RailTimeout(Exception):
    """Raised when the biller does not respond in time.

    The *caller* must treat this as an indeterminate outcome:
    the biller may or may not have processed the payment.
    """

    pass


@dataclass
class RailResult:
    """Return value from a rail submission attempt."""

    status: RailStatus
    rail_reference: str


class RailClient:
    """Abstract interface for an external payment rail.

    Concrete implementations decide how to communicate with the biller.
    """

    def submit_payment(
        self, rail_reference: str, biller_code: str, amount: Decimal
    ) -> RailResult:
        raise NotImplementedError

    def get_status(self, rail_reference: str) -> RailStatus:
        raise NotImplementedError


class MockRailClient(RailClient):
    """In-process mock that uses the rail DB tables directly.

    Could later be replaced by a real HTTP client calling a biller API.
    """

    def __init__(self, db: Session) -> None:
        self._db = db

    def _get_biller(self, biller_code: str) -> RailBiller:
        stmt = select(RailBiller).where(
            RailBiller.code == biller_code,
            RailBiller.is_active.is_(True),
        )
        biller = self._db.scalar(stmt)
        if not biller:
            raise ValueError(f"Unknown or inactive biller: {biller_code}")
        return biller

    def submit_payment(
        self, rail_reference: str, biller_code: str, amount: Decimal
    ) -> RailResult:
        """Submit a payment to the mock biller.

        IDEMPOTENCY: If a rail_record with this rail_reference already exists,
        return its stored status instead of processing again.  This models a
        rail that supports idempotent submissions.
        """
        # Check for existing record (idempotent replay)
        existing = self._db.scalar(
            select(RailRecord).where(RailRecord.rail_reference == rail_reference)
        )
        if existing:
            return RailResult(
                status=RailStatus(existing.status.value),
                rail_reference=rail_reference,
            )

        biller = self._get_biller(biller_code)

        if biller.failure_mode == FailureMode.OK:
            record = RailRecord(
                rail_reference=rail_reference,
                biller_id=biller.id,
                amount=amount,
                status=RailRecordStatus.SETTLED,
            )
            self._db.add(record)
            self._db.commit()
            return RailResult(status=RailStatus.SETTLED, rail_reference=rail_reference)

        elif biller.failure_mode == FailureMode.DECLINE:
            record = RailRecord(
                rail_reference=rail_reference,
                biller_id=biller.id,
                amount=amount,
                status=RailRecordStatus.FAILED,
            )
            self._db.add(record)
            self._db.commit()
            return RailResult(status=RailStatus.FAILED, rail_reference=rail_reference)

        elif biller.failure_mode == FailureMode.TIMEOUT_AFTER_PROCESS:
            # Biller records SETTLED, then connection times out: we never hear back.
            record = RailRecord(
                rail_reference=rail_reference,
                biller_id=biller.id,
                amount=amount,
                status=RailRecordStatus.SETTLED,
            )
            self._db.add(record)
            self._db.commit()
            raise RailTimeout(
                f"Timeout after biller processed payment {rail_reference}"
            )

        elif biller.failure_mode == FailureMode.TIMEOUT_BEFORE_PROCESS:
            # Biller never receives the payment — nothing is recorded.
            raise RailTimeout(
                f"Timeout before biller received payment {rail_reference}"
            )

        raise ValueError(f"Unknown failure mode: {biller.failure_mode}")

    def get_status(self, rail_reference: str) -> RailStatus:
        """Query the biller's ledger for the outcome of a previous submission."""
        record = self._db.scalar(
            select(RailRecord).where(RailRecord.rail_reference == rail_reference)
        )
        if not record:
            return RailStatus.NOT_FOUND
        return RailStatus(record.status.value)
