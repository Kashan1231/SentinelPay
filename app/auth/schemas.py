"""
SentinelPay – Pydantic schemas for authentication and user management.
"""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, model_validator

from app.auth.models import UserRole
from app.auth.security import validate_password_policy


class UserCreate(BaseModel):
    """Payload required to register a new user.
    Strictly forbids extra fields to prevent mass assignment.
    """

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str
    full_name: str

    @model_validator(mode="after")
    def validate_password(self) -> "UserCreate":
        validate_password_policy(self.password, str(self.email))
        return self


class UserResponse(BaseModel):
    """User representation returned by public/protected endpoints.
    NEVER includes hashed_password.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    """JWT response token schema."""

    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Internal decoded JWT payload."""

    sub: str | None = None
    role: UserRole | None = None
