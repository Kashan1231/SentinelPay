"""
Unit and integration tests for Phase 2: Auth and Authorization endpoints.

Tests coverage:
  - User registration success
  - Duplicate email registration rejection (HTTP 400)
  - Login success returning JWT token
  - Login failure on wrong password (HTTP 401)
  - GET /auth/me with valid token returning user details
  - GET /auth/me with no token or invalid token (HTTP 401)
  - Role-based authorization dependency (require_role) verification
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.auth.dependencies import require_role
from app.auth.models import UserRole
from app.core.database import Base, get_db
from app.main import app

from conftest import client



# Dummy role-protected test route to verify require_role dependency
@app.get("/test-admin-only", tags=["Test"])
def admin_only_route(current_user=pytest.importorskip("fastapi").Depends(require_role(UserRole.ADMIN))):
    return {"message": "Welcome Admin"}


# ── Test Cases ───────────────────────────────────────────

def test_register_user_success() -> None:
    """POST /auth/register should create a user and return UserResponse without hashed_password."""
    payload = {
        "email": "alice@example.com",
        "password": "SecurePassword123!",
        "full_name": "Alice Smith",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["email"] == "alice@example.com"
    assert data["full_name"] == "Alice Smith"
    assert data["role"] == "customer"
    assert data["is_active"] is True
    assert "id" in data
    assert "hashed_password" not in data


def test_register_duplicate_email_fails() -> None:
    """POST /auth/register should reject duplicate emails with 400 Bad Request."""
    payload = {
        "email": "duplicate@example.com",
        "password": "Password123!",
        "full_name": "User One",
    }
    first_res = client.post("/auth/register", json=payload)
    assert first_res.status_code == 201

    duplicate_res = client.post("/auth/register", json=payload)
    assert duplicate_res.status_code == 400
    assert duplicate_res.json()["detail"] == "Email already registered"


def test_login_success_returns_token() -> None:
    """POST /auth/login with valid credentials should return access_token and token_type."""
    register_payload = {
        "email": "bob@example.com",
        "password": "BobPassword123!",
        "full_name": "Bob Jones",
    }
    client.post("/auth/register", json=register_payload)

    login_payload = {
        "username": "bob@example.com",
        "password": "BobPassword123!",
    }
    response = client.post("/auth/login", data=login_payload)
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20


def test_login_wrong_password_fails() -> None:
    """POST /auth/login with wrong password should fail with 401 Unauthorized."""
    register_payload = {
        "email": "charlie@example.com",
        "password": "RightPassword123!",
        "full_name": "Charlie Brown",
    }
    client.post("/auth/register", json=register_payload)

    login_payload = {
        "username": "charlie@example.com",
        "password": "WrongPassword123!",
    }
    response = client.post("/auth/login", data=login_payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_get_me_valid_token_success() -> None:
    """GET /auth/me with valid Bearer token returns current user details."""
    register_payload = {
        "email": "diana@example.com",
        "password": "DianaPassword123!",
        "full_name": "Diana Prince",
    }
    client.post("/auth/register", json=register_payload)

    login_res = client.post("/auth/login", data={"username": "diana@example.com", "password": "DianaPassword123!"})
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/auth/me", headers=headers)
    assert me_res.status_code == 200

    user_data = me_res.json()
    assert user_data["email"] == "diana@example.com"
    assert user_data["full_name"] == "Diana Prince"
    assert "hashed_password" not in user_data


def test_get_me_no_token_or_bad_token_fails_401() -> None:
    """GET /auth/me without token or invalid token returns 401 Unauthorized."""
    # No token
    no_token_res = client.get("/auth/me")
    assert no_token_res.status_code == 401

    # Invalid token
    bad_token_headers = {"Authorization": "Bearer invalid_token_12345"}
    bad_token_res = client.get("/auth/me", headers=bad_token_headers)
    assert bad_token_res.status_code == 401


def test_role_authorization_enforcement() -> None:
    """Customer role user should be rejected (403) on admin-only route."""
    register_payload = {
        "email": "customer@example.com",
        "password": "CustomerPass123!",
        "full_name": "Regular Customer",
    }
    client.post("/auth/register", json=register_payload)
    login_res = client.post("/auth/login", data={"username": "customer@example.com", "password": "CustomerPass123!"})
    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    admin_route_res = client.get("/test-admin-only", headers=headers)
    assert admin_route_res.status_code == 403
