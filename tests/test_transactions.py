"""
Unit and integration tests for Phase 4 & Phase 5: Transactions Engine, Atomic Money Transfers & Idempotency Keys.

Test cases covered:
  - Successful money transfer with Idempotency-Key header
  - Insufficient funds transfer rejection (HTTP 400)
  - Transfer to non-existent account number failure (HTTP 404)
  - Transfer using an account belonging to someone else failure (HTTP 403)
  - Transfer to the same account failure (HTTP 400)
  - Transfer with zero or negative amount failure (HTTP 400/422)
  - Transaction history filtering
  - Missing Idempotency-Key header rejection (HTTP 400)
  - Same Idempotency-Key + same payload replays stored response without double debiting
  - Same Idempotency-Key + different payload returns HTTP 409 Conflict
  - Different Idempotency-Keys execute transfers normally
"""

from decimal import Decimal
import uuid

import pytest
from conftest import TestSession, client

from app.accounts.models import Account
from app.auth.models import User, UserRole
from app.auth.security import hash_password


# ── Helper Fixtures & Setup ────────────────────────────────

def get_auth_headers(email: str, password: str = "Password123!", idempotency_key: str | None = None) -> dict[str, str]:
    """Helper to log in a user and return Authorization + optional Idempotency-Key headers."""
    login_res = client.post("/auth/login", data={"username": email, "password": password})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    elif idempotency_key is not False:
        headers["Idempotency-Key"] = str(uuid.uuid4())
    return headers


def seed_user_and_account(
    email: str,
    full_name: str,
    initial_balance: str = "0.00",
    password: str = "Password123!",
) -> tuple[int, int, str]:
    """Seed a user and their account directly in the test database, returning (user_id, account_id, account_number)."""
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


# ── Test Cases ───────────────────────────────────────────

def test_successful_transfer() -> None:
    """Successful transfer should update balances on both accounts and create a completed transaction record."""
    _, sender_acc_id, sender_acc_num = seed_user_and_account("sender1@example.com", "Sender One", "500.00")
    _, recipient_acc_id, recipient_acc_num = seed_user_and_account("recipient1@example.com", "Recipient One", "100.00")

    headers_sender = get_auth_headers("sender1@example.com")

    payload = {
        "recipient_account_number": recipient_acc_num,
        "amount": "150.50",
        "description": "Payment for dinner",
    }
    response = client.post("/transactions", json=payload, headers=headers_sender)
    assert response.status_code == 201

    data = response.json()
    assert data["amount"] == "150.50"
    assert data["status"] == "completed"
    assert data["sender_account_id"] == sender_acc_id
    assert data["recipient_account_id"] == recipient_acc_id
    assert data["completed_at"] is not None
    assert data["transaction_ref"].startswith("TX-")

    # Verify database balances
    db = TestSession()
    s_acc = db.get(Account, sender_acc_id)
    r_acc = db.get(Account, recipient_acc_id)
    assert s_acc.balance == Decimal("349.50")
    assert r_acc.balance == Decimal("250.50")
    db.close()


def test_insufficient_funds_rejected() -> None:
    """Transfer exceeding available sender balance must fail with 400 and leave balances untouched."""
    _, sender_acc_id, sender_acc_num = seed_user_and_account("broke_sender@example.com", "Broke Sender", "50.00")
    _, recipient_acc_id, recipient_acc_num = seed_user_and_account("rich_recip@example.com", "Rich Recip", "200.00")

    headers_sender = get_auth_headers("broke_sender@example.com")

    payload = {
        "recipient_account_number": recipient_acc_num,
        "amount": "100.00",
    }
    response = client.post("/transactions", json=payload, headers=headers_sender)
    assert response.status_code == 400
    assert response.json()["detail"] == "Insufficient funds"

    # Verify database balances were completely untouched
    db = TestSession()
    s_acc = db.get(Account, sender_acc_id)
    r_acc = db.get(Account, recipient_acc_id)
    assert s_acc.balance == Decimal("50.00")
    assert r_acc.balance == Decimal("200.00")
    db.close()


def test_transfer_to_nonexistent_account_fails() -> None:
    """Transfer to a recipient account number that does not exist should return 404 Not Found."""
    seed_user_and_account("valid_sender@example.com", "Valid Sender", "1000.00")
    headers_sender = get_auth_headers("valid_sender@example.com")

    payload = {
        "recipient_account_number": "9999999999",
        "amount": "50.00",
    }
    response = client.post("/transactions", json=payload, headers=headers_sender)
    assert response.status_code == 404
    assert response.json()["detail"] == "Recipient account not found"


def test_transfer_using_other_users_account_fails() -> None:
    """Specifying a sender_account_id that belongs to another user should fail with 403 Forbidden."""
    _, other_user_acc_id, _ = seed_user_and_account("victim@example.com", "Victim User", "1000.00")
    _, attacker_user_acc_id, attacker_acc_num = seed_user_and_account("attacker@example.com", "Attacker User", "0.00")

    headers_attacker = get_auth_headers("attacker@example.com")

    payload = {
        "sender_account_id": other_user_acc_id,
        "recipient_account_number": attacker_acc_num,
        "amount": "500.00",
    }
    response = client.post("/transactions", json=payload, headers=headers_attacker)
    assert response.status_code == 403
    assert response.json()["detail"] == "Sender account does not belong to the current user"


def test_transfer_to_self_same_account_fails() -> None:
    """Attempting to transfer money to the exact same account should fail with 400 Bad Request."""
    _, acc_id, acc_num = seed_user_and_account("self_sender@example.com", "Self Sender", "500.00")
    headers_sender = get_auth_headers("self_sender@example.com")

    payload = {
        "recipient_account_number": acc_num,
        "amount": "50.00",
    }
    response = client.post("/transactions", json=payload, headers=headers_sender)
    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot transfer money to the same account"


def test_transfer_negative_or_zero_amount_fails() -> None:
    """Transfer with 0.00 or negative amount must be rejected."""
    _, _, recip_acc_num = seed_user_and_account("zero_recip@example.com", "Zero Recip", "100.00")
    seed_user_and_account("zero_sender@example.com", "Zero Sender", "500.00")
    headers_sender = get_auth_headers("zero_sender@example.com")

    # Zero amount
    res_zero = client.post("/transactions", json={"recipient_account_number": recip_acc_num, "amount": "0.00"}, headers=headers_sender)
    assert res_zero.status_code in [400, 422]

    # Negative amount
    res_neg = client.post("/transactions", json={"recipient_account_number": recip_acc_num, "amount": "-25.00"}, headers=headers_sender)
    assert res_neg.status_code in [400, 422]


def test_transaction_history_filtering() -> None:
    """GET /transactions should return only transactions where user is sender or recipient."""
    _, sender_acc_id, sender_acc_num = seed_user_and_account("hist_user1@example.com", "Hist One", "1000.00")
    _, recip_acc_id, recip_acc_num = seed_user_and_account("hist_user2@example.com", "Hist Two", "500.00")
    seed_user_and_account("unrelated@example.com", "Unrelated User", "100.00")

    headers_user1 = get_auth_headers("hist_user1@example.com")
    headers_user2 = get_auth_headers("hist_user2@example.com")
    headers_unrelated = get_auth_headers("unrelated@example.com")

    # Perform transfer from User 1 to User 2
    tx_res = client.post("/transactions", json={"recipient_account_number": recip_acc_num, "amount": "200.00"}, headers=headers_user1)
    assert tx_res.status_code == 201

    # User 1 history should contain 1 transaction
    res1 = client.get("/transactions", headers=headers_user1)
    assert res1.status_code == 200
    assert len(res1.json()) == 1
    assert res1.json()[0]["amount"] == "200.00"

    # User 2 history should also contain 1 transaction (received)
    res2 = client.get("/transactions", headers=headers_user2)
    assert res2.status_code == 200
    assert len(res2.json()) == 1
    assert res2.json()[0]["amount"] == "200.00"

    # Unrelated user history should be empty
    res_unrelated = client.get("/transactions", headers=headers_unrelated)
    assert res_unrelated.status_code == 200
    assert len(res_unrelated.json()) == 0


# ── Idempotency Tests ────────────────────────────────────

def test_missing_idempotency_key_header_returns_400() -> None:
    """POST /transactions without Idempotency-Key header must return HTTP 400 Bad Request."""
    _, _, recip_num = seed_user_and_account("nokey_recip@example.com", "No Key Recip", "100.00")
    seed_user_and_account("nokey_sender@example.com", "No Key Sender", "500.00")

    # Explicitly get headers without Idempotency-Key
    headers = get_auth_headers("nokey_sender@example.com", idempotency_key=False)

    payload = {"recipient_account_number": recip_num, "amount": "50.00"}
    res = client.post("/transactions", json=payload, headers=headers)
    assert res.status_code == 400
    assert res.json()["detail"] == "Missing Idempotency-Key header"


def test_idempotency_same_key_same_payload_replays_response() -> None:
    """Same Idempotency-Key + same payload must execute transfer ONLY ONCE and return identical cached response."""
    _, sender_id, _ = seed_user_and_account("idem_sender1@example.com", "Idem Sender 1", "500.00")
    _, recip_id, recip_num = seed_user_and_account("idem_recip1@example.com", "Idem Recip 1", "100.00")

    key = str(uuid.uuid4())
    headers = get_auth_headers("idem_sender1@example.com", idempotency_key=key)

    payload = {"recipient_account_number": recip_num, "amount": "100.00"}

    # First request -> executes transfer
    res1 = client.post("/transactions", json=payload, headers=headers)
    assert res1.status_code == 201
    data1 = res1.json()

    # Second request with SAME key & SAME payload -> returns stored response without re-transferring
    res2 = client.post("/transactions", json=payload, headers=headers)
    assert res2.status_code == 201
    data2 = res2.json()

    assert data1["id"] == data2["id"]
    assert data1["transaction_ref"] == data2["transaction_ref"]

    # Assert database balances changed ONLY ONCE ($500 -> $400, $100 -> $200)
    db = TestSession()
    s_acc = db.get(Account, sender_id)
    r_acc = db.get(Account, recip_id)
    assert s_acc.balance == Decimal("400.00")
    assert r_acc.balance == Decimal("200.00")
    db.close()


def test_idempotency_same_key_different_payload_returns_409() -> None:
    """Same Idempotency-Key + DIFFERENT payload must be rejected with HTTP 409 Conflict."""
    _, _, recip_num1 = seed_user_and_account("diff_recip1@example.com", "Diff Recip 1", "100.00")
    _, _, recip_num2 = seed_user_and_account("diff_recip2@example.com", "Diff Recip 2", "100.00")
    seed_user_and_account("diff_sender@example.com", "Diff Sender", "500.00")

    key = str(uuid.uuid4())
    headers = get_auth_headers("diff_sender@example.com", idempotency_key=key)

    payload1 = {"recipient_account_number": recip_num1, "amount": "50.00"}
    payload2 = {"recipient_account_number": recip_num2, "amount": "100.00"}

    # First request
    res1 = client.post("/transactions", json=payload1, headers=headers)
    assert res1.status_code == 201

    # Second request with SAME key but DIFFERENT payload -> 409 Conflict
    res2 = client.post("/transactions", json=payload2, headers=headers)
    assert res2.status_code == 409
    assert res2.json()["detail"] == "Idempotency key reused with a different request"


def test_idempotency_different_keys_both_succeed() -> None:
    """Different Idempotency-Keys for distinct transfers should both execute successfully."""
    _, sender_id, _ = seed_user_and_account("multi_sender@example.com", "Multi Sender", "500.00")
    _, recip_id, recip_num = seed_user_and_account("multi_recip@example.com", "Multi Recip", "100.00")

    key1 = str(uuid.uuid4())
    key2 = str(uuid.uuid4())

    headers1 = get_auth_headers("multi_sender@example.com", idempotency_key=key1)
    headers2 = get_auth_headers("multi_sender@example.com", idempotency_key=key2)

    payload = {"recipient_account_number": recip_num, "amount": "100.00"}

    res1 = client.post("/transactions", json=payload, headers=headers1)
    assert res1.status_code == 201

    res2 = client.post("/transactions", json=payload, headers=headers2)
    assert res2.status_code == 201

    assert res1.json()["id"] != res2.json()["id"]

    # Verify both transfers subtracted balance ($500 -> $300, $100 -> $300)
    db = TestSession()
    s_acc = db.get(Account, sender_id)
    r_acc = db.get(Account, recip_id)
    assert s_acc.balance == Decimal("300.00")
    assert r_acc.balance == Decimal("300.00")
    db.close()
