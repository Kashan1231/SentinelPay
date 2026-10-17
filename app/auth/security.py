"""
SentinelPay – Security utilities for password hashing and JWT token handling.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import settings


# Precomputed valid bcrypt hash for constant-time dummy verification on unknown emails
_DUMMY_BCRYPT_HASH = "$2b$12$e8k8h9vK8h9vK8h9vK8h9e7Zq3qY3qY3qY3qY3qY3qY3qY3qY3qY3"

COMMON_PASSWORDS = {
    "password",
    "password123",
    "password1234",
    "1234567890",
    "123456789",
    "12345678",
    "qwertyuiop",
    "admin12345",
    "administrator",
    "welcome123",
    "iloveyou123",
}


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against the stored bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def dummy_verify_password(plain_password: str) -> bool:
    """Perform a constant-time dummy verification to mitigate email enumeration attacks."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), _DUMMY_BCRYPT_HASH.encode("utf-8"))
    except Exception:
        return False


def validate_password_policy(password: str, email: str | None = None) -> None:
    """Validate password against security policy:
    - Min 10 characters
    - Max 72 BYTES (bcrypt truncation limit)
    - Must not equal email (case-insensitive)
    - Must not be in common passwords list
    """
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long")

    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 bytes (bcrypt limit)")

    if email and password.strip().lower() == email.strip().lower():
        raise ValueError("Password must not be identical to email address")

    if password.strip().lower() in COMMON_PASSWORDS:
        raise ValueError("Password is too common or easily guessable")


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """
    Encode a JWT access token containing subject claims and expiration time.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """
    Decode and verify a JWT access token.
    Returns payload dictionary if valid, or None if invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.PyJWTError:
        return None
