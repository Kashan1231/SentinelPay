"""
Integration tests for Phase 5: Concurrency Protection & Row-Level Locking.

Tests coverage:
  - Concurrent transfer race condition: two simultaneous transfers of $80.00 from an account
    with $100.00 starting balance. Row-level locks (SELECT ... FOR UPDATE) force serialization:
    exactly ONE transfer succeeds, ONE is rejected with HTTP 400 Insufficient funds, and final balance is $20.00.
  - Bidirectional concurrent transfers: simultaneous transfers in opposite directions between the same
    two accounts (Account A -> B and Account B -> A) execute cleanly without deadlocks due to deterministic lock ordering.
"""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import uuid

import pytest
from fastapi.testclient import TestClient
from conftest import TestSession, client
from app.main import app

from app.accounts.models import Account
from app.auth.models import User, UserRole
from app.auth.security import hash_password


def seed_user_and_account(
    email: str,
    full_name: str,
    initial_balance: str = "0.00",
    password: str = "Password123!",
) -> tuple[int, int, str]:
    """Seed user and account directly in test database."""
    db = TestSession()
    user = User(
        email=email,
        hashed_password=hash_password(password),
        full_name=full_name,
        role=UserRole.CUSTOMER,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    account = Account(
        user_id=user.id,
        account_number=f"{user.id:010d}",
        account_type="checking",
        balance=Decimal(initial_balance),
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    u_id, a_id, a_num = user.id, account.id, account.account_number
    db.close()
    return u_id, a_id, a_num


def get_auth_headers(email: str, password: str = "Password123!") -> dict[str, str]:
    """Log in and return headers."""
    login_res = client.post("/auth/login", data={"username": email, "password": password})
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_concurrent_transfers_race_condition() -> None:
    """
    Simulate two concurrent transfer requests of $80.00 from a sender account with $100.00 balance.
    Assert that row-level locking serializes execution: exactly one succeeds and one fails with 400 Insufficient funds.
    """
    _, sender_acc_id, sender_acc_num = seed_user_and_account("race_sender@example.com", "Race Sender", "100.00")
    _, recip_acc_id, recip_acc_num = seed_user_and_account("race_recip@example.com", "Race Recip", "50.00")

    headers = get_auth_headers("race_sender@example.com")

    payload1 = {"recipient_account_number": recip_acc_num, "amount": "80.00"}
    payload2 = {"recipient_account_number": recip_acc_num, "amount": "80.00"}

    def make_transfer(payload: dict, key: str):
        # Use a fresh client per thread — shared TestClient is not thread-safe
        with TestClient(app) as thread_client:
            req_headers = {**headers, "Idempotency-Key": key}
            return thread_client.post("/transactions", json=payload, headers=req_headers)

    key1 = str(uuid.uuid4())
    key2 = str(uuid.uuid4())

    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(make_transfer, payload1, key1)
        future2 = executor.submit(make_transfer, payload2, key2)

        res1 = future1.result(timeout=30)
        res2 = future2.result(timeout=30)

    statuses = sorted([res1.status_code, res2.status_code])
    assert statuses == [201, 400], f"Expected one 201 and one 400, got {statuses}"

    # Verify final sender balance is exactly $20.00 (not negative -$60.00)
    db = TestSession()
    sender_acc = db.get(Account, sender_acc_id)
    recip_acc = db.get(Account, recip_acc_id)
    assert sender_acc.balance == Decimal("20.00")
    assert recip_acc.balance == Decimal("130.00")
    db.close()


def test_bidirectional_concurrent_transfers_no_deadlock() -> None:
    """
    Simulate simultaneous transfers in opposite directions:
      Account A -> Account B ($30.00)
      Account B -> Account A ($40.00)
    Deterministic lock ordering (min ID first, max ID second) guarantees no deadlocks occur.
    """
    user_a_id, acc_a_id, acc_a_num = seed_user_and_account("user_a@example.com", "User A", "100.00")
    user_b_id, acc_b_id, acc_b_num = seed_user_and_account("user_b@example.com", "User B", "100.00")

    headers_a = get_auth_headers("user_a@example.com")
    headers_b = get_auth_headers("user_b@example.com")

    payload_a_to_b = {"recipient_account_number": acc_b_num, "amount": "30.00"}
    payload_b_to_a = {"recipient_account_number": acc_a_num, "amount": "40.00"}

    def transfer_a():
        # Use a fresh client per thread — shared TestClient is not thread-safe
        with TestClient(app) as thread_client:
            return thread_client.post("/transactions", json=payload_a_to_b, headers={**headers_a, "Idempotency-Key": str(uuid.uuid4())})

    def transfer_b():
        with TestClient(app) as thread_client:
            return thread_client.post("/transactions", json=payload_b_to_a, headers={**headers_b, "Idempotency-Key": str(uuid.uuid4())})

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(transfer_a)
        future_b = executor.submit(transfer_b)

        res_a = future_a.result(timeout=30)
        res_b = future_b.result(timeout=30)

    assert res_a.status_code == 201
    assert res_b.status_code == 201

    # Verify final balances:
    # Account A: $100 - $30 + $40 = $110.00
    # Account B: $100 - $40 + $30 = $90.00
    db = TestSession()
    acc_a = db.get(Account, acc_a_id)
    acc_b = db.get(Account, acc_b_id)
    assert acc_a.balance == Decimal("110.00")
    assert acc_b.balance == Decimal("90.00")
    db.close()
