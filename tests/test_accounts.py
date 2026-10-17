"""
Unit and integration tests for Phase 3: Accounts endpoints & ownership authorization.

Test cases covered:
  - Authenticated user can create a bank account (201 Created)
  - Unauthenticated request to /accounts is rejected (401 Unauthorized)
  - Customer can list only their own accounts, not other users' accounts
  - Customer cannot view another user's account by ID (403 Forbidden)
  - Admin CAN view another user's account by ID (200 OK)
  - Non-admin user cannot access /accounts/all (403 Forbidden)
  - Admin user CAN access /accounts/all (200 OK)
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.auth.models import User, UserRole
from app.auth.security import hash_password
from app.core.database import Base, get_db
from app.main import app

from conftest import TestSession, client


# ── Helper Fixtures & Setup ────────────────────────────────

def get_auth_headers(email: str, password: str = "Password123!") -> dict[str, str]:
    """Helper to log in a user and return Authorization headers."""
    login_res = client.post("/auth/login", data={"username": email, "password": password})
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ── Test Cases ───────────────────────────────────────────

def test_unauthenticated_request_rejected() -> None:
    """POST and GET /accounts without token should return 401 Unauthorized."""
    res_post = client.post("/accounts", json={"account_type": "checking"})
    assert res_post.status_code == 401

    res_get = client.get("/accounts")
    assert res_get.status_code == 401


def test_authenticated_user_create_account() -> None:
    """Authenticated user should be able to create a checking account with starting balance 0.00."""
    reg_payload = {"email": "acc_user1@example.com", "password": "Password123!", "full_name": "Acc User One"}
    client.post("/auth/register", json=reg_payload)
    headers = get_auth_headers("acc_user1@example.com")

    res = client.post("/accounts", json={"account_type": "checking"}, headers=headers)
    assert res.status_code == 201

    data = res.json()
    assert data["account_type"] == "checking"
    assert data["balance"] == "0.00"
    assert data["status"] == "active"
    assert len(data["account_number"]) == 10
    assert "id" in data


def test_user_list_only_own_accounts() -> None:
    """GET /accounts should return only accounts belonging to the current user."""
    # Register User A & User B
    client.post("/auth/register", json={"email": "usera@example.com", "password": "Password123!", "full_name": "User A"})
    client.post("/auth/register", json={"email": "userb@example.com", "password": "Password123!", "full_name": "User B"})

    headers_a = get_auth_headers("usera@example.com")
    headers_b = get_auth_headers("userb@example.com")

    # Create account for User A
    client.post("/accounts", json={"account_type": "savings"}, headers=headers_a)

    # Create 2 accounts for User B
    client.post("/accounts", json={"account_type": "checking"}, headers=headers_b)
    client.post("/accounts", json={"account_type": "savings"}, headers=headers_b)

    # List User A's accounts
    res_a = client.get("/accounts", headers=headers_a)
    assert res_a.status_code == 200
    assert len(res_a.json()) == 1
    assert res_a.json()[0]["account_type"] == "savings"

    # List User B's accounts
    res_b = client.get("/accounts", headers=headers_b)
    assert res_b.status_code == 200
    assert len(res_b.json()) == 2


def test_user_cannot_access_another_users_account_by_id() -> None:
    """Customer B trying to GET /accounts/{id_of_user_a} should be rejected with 403 Forbidden."""
    # Register users and accounts independently (DB is wiped between tests)
    client.post("/auth/register", json={"email": "usera@example.com", "password": "Password123!", "full_name": "User A"})
    client.post("/auth/register", json={"email": "userb@example.com", "password": "Password123!", "full_name": "User B"})
    headers_a = get_auth_headers("usera@example.com")
    headers_b = get_auth_headers("userb@example.com")
    client.post("/accounts", json={"account_type": "savings"}, headers=headers_a)

    # Get User A's account ID
    acc_a = client.get("/accounts", headers=headers_a).json()[0]
    acc_a_id = acc_a["id"]

    # User B attempts to view User A's account
    forbidden_res = client.get(f"/accounts/{acc_a_id}", headers=headers_b)
    assert forbidden_res.status_code == 403
    assert forbidden_res.json()["detail"] == "Access forbidden: You do not own this account"


def test_admin_can_access_another_users_account_by_id() -> None:
    """Admin user CAN access any user's account by ID."""
    # Seed regular user + account
    client.post("/auth/register", json={"email": "usera@example.com", "password": "Password123!", "full_name": "User A"})
    headers_a = get_auth_headers("usera@example.com")
    client.post("/accounts", json={"account_type": "savings"}, headers=headers_a)

    # Seed admin directly in DB
    db = TestSession()
    admin = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPass123!"),
        full_name="Admin User",
        role=UserRole.ADMIN,
    )
    db.add(admin)
    db.commit()
    db.close()

    headers_admin = get_auth_headers("admin@example.com", "AdminPass123!")
    acc_a_id = client.get("/accounts", headers=headers_a).json()[0]["id"]

    admin_res = client.get(f"/accounts/{acc_a_id}", headers=headers_admin)
    assert admin_res.status_code == 200
    assert admin_res.json()["id"] == acc_a_id


def test_non_admin_cannot_access_accounts_all() -> None:
    """Customer user hitting GET /accounts/all should be rejected with 403 Forbidden."""
    client.post("/auth/register", json={"email": "usera@example.com", "password": "Password123!", "full_name": "User A"})
    headers_a = get_auth_headers("usera@example.com")
    res = client.get("/accounts/all", headers=headers_a)
    assert res.status_code == 403


def test_admin_can_access_accounts_all() -> None:
    """Admin user hitting GET /accounts/all should get all accounts system-wide."""
    # Seed 3 regular users with accounts
    for i in range(1, 4):
        client.post("/auth/register", json={"email": f"alluser{i}@example.com", "password": "Password123!", "full_name": f"User {i}"})
        h = get_auth_headers(f"alluser{i}@example.com")
        client.post("/accounts", json={"account_type": "checking"}, headers=h)

    # Seed admin
    db = TestSession()
    admin = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPass123!"),
        full_name="Admin User",
        role=UserRole.ADMIN,
    )
    db.add(admin)
    db.commit()
    db.close()

    headers_admin = get_auth_headers("admin@example.com", "AdminPass123!")
    res = client.get("/accounts/all", headers=headers_admin)
    assert res.status_code == 200
    assert len(res.json()) >= 3
