"""
SentinelPay – Router endpoints for registration, login, user profile, and admin user management.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record_event, record_event_independent
from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.auth.schemas import Token, UserCreate, UserResponse
from app.auth.security import (
    create_access_token,
    dummy_verify_password,
    hash_password,
    verify_password,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import check_rate_limit

router = APIRouter(prefix="/auth", tags=["Auth"])
admin_router = APIRouter(prefix="/admin/users", tags=["Admin Users"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Register a new user with email, password, and full name.
    Rejects duplicate emails with a 400 error.
    Strictly prevents mass-assignment of role, is_active, or balance.
    """
    # Rate limiting on registration
    check_rate_limit(
        request=request,
        endpoint_key="register",
        key_type="ip",
        max_requests=settings.RATE_LIMIT_REGISTER_MAX,
        window_seconds=settings.RATE_LIMIT_REGISTER_WINDOW_SECONDS,
        db=db,
    )

    stmt = select(User).where(User.email == user_in.email.lower())
    existing_user = db.scalar(stmt)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = User(
        email=user_in.email.lower(),
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name,
        role=UserRole.CUSTOMER,
        is_active=True,
    )
    db.add(user)
    db.flush()

    ip_address = request.client.host if request.client else None
    record_event(
        db=db,
        event_type="USER_REGISTERED",
        actor_user_id=user.id,
        actor_role=user.role.value,
        entity_type="user",
        entity_id=str(user.id),
        outcome="SUCCESS",
        details={"email": user.email, "role": user.role.value},
        ip_address=ip_address,
    )

    db.commit()
    db.refresh(user)

    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Log in to obtain JWT access token",
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Authenticate user via email (username field) and password.
    Enforces account lockout after LOGIN_MAX_FAILURES consecutive failed attempts.
    Mitigates user-enumeration timing attacks on unknown emails.
    Returns a JWT access token upon success.
    """
    ip_address = request.client.host if request.client else None
    now_utc = datetime.now(timezone.utc)

    # Per-IP rate limiting on login
    check_rate_limit(
        request=request,
        endpoint_key="login",
        key_type="ip",
        max_requests=settings.RATE_LIMIT_LOGIN_MAX,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        db=db,
    )

    email = form_data.username.lower()
    stmt = select(User).where(User.email == email)
    user = db.scalar(stmt)

    # 1. Unknown email: constant-time dummy verification and generic 401
    if not user:
        dummy_verify_password(form_data.password)
        record_event_independent(
            event_type="LOGIN_FAILED",
            actor_user_id=None,
            actor_role=None,
            entity_type="user",
            entity_id=None,
            outcome="FAILURE",
            details={"attempted_email": form_data.username},
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Check if account is currently locked
    if user.locked_until:
        locked_until_utc = (
            user.locked_until
            if user.locked_until.tzinfo
            else user.locked_until.replace(tzinfo=timezone.utc)
        )
        if locked_until_utc > now_utc:
            retry_after = max(1, int((locked_until_utc - now_utc).total_seconds()) + 1)
            record_event_independent(
                event_type="LOGIN_BLOCKED_LOCKED",
                actor_user_id=user.id,
                actor_role=user.role.value,
                entity_type="user",
                entity_id=str(user.id),
                outcome="DENIED",
                details={"email": user.email, "retry_after": retry_after},
                ip_address=ip_address,
                db=db,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account is temporarily locked due to multiple failed login attempts. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        else:
            # Lockout expired naturally
            user.locked_until = None
            user.failed_login_count = 0
            db.commit()

    # 3. Verify password
    if not verify_password(form_data.password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.LOGIN_MAX_FAILURES:
            user.locked_until = now_utc + timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
            db.commit()
            record_event_independent(
                event_type="ACCOUNT_LOCKED",
                actor_user_id=user.id,
                actor_role=user.role.value,
                entity_type="user",
                entity_id=str(user.id),
                outcome="FAILURE",
                details={
                    "email": user.email,
                    "failed_attempts": user.failed_login_count,
                    "lockout_seconds": settings.LOGIN_LOCKOUT_SECONDS,
                },
                ip_address=ip_address,
                db=db,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account is temporarily locked due to multiple failed login attempts. Please try again later.",
                headers={"Retry-After": str(settings.LOGIN_LOCKOUT_SECONDS)},
            )
        else:
            db.commit()
            record_event_independent(
                event_type="LOGIN_FAILED",
                actor_user_id=user.id,
                actor_role=user.role.value,
                entity_type="user",
                entity_id=str(user.id),
                outcome="FAILURE",
                details={
                    "attempted_email": form_data.username,
                    "failed_attempts": user.failed_login_count,
                },
                ip_address=ip_address,
                db=db,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 4. Successful login: reset failed login counter & lockout timestamp
    if user.failed_login_count > 0 or user.locked_until is not None:
        user.failed_login_count = 0
        user.locked_until = None
        db.commit()

    if not user.is_active:
        record_event_independent(
            event_type="LOGIN_FAILED",
            actor_user_id=user.id,
            actor_role=user.role.value,
            entity_type="user",
            entity_id=str(user.id),
            outcome="FAILURE",
            details={"attempted_email": form_data.username, "reason": "Inactive user account"},
            ip_address=ip_address,
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account",
        )

    record_event(
        db=db,
        event_type="LOGIN_SUCCESS",
        actor_user_id=user.id,
        actor_role=user.role.value,
        entity_type="user",
        entity_id=str(user.id),
        outcome="SUCCESS",
        details={"email": user.email},
        ip_address=ip_address,
    )
    db.commit()

    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    """
    Retrieve profile details for the currently logged-in user.
    """
    return current_user


# ─────────────────────────────────────────────────────────────
# ADMIN USER MANAGEMENT (Phase 10)
# ─────────────────────────────────────────────────────────────

@admin_router.post(
    "/{user_id}/unlock",
    response_model=UserResponse,
    summary="Unlock a temporarily locked user account (Admin only)",
)
def unlock_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    """
    Manually clear account lockout for a user and reset failed login counter.
    Restricted strictly to administrators.
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    user.failed_login_count = 0
    user.locked_until = None

    ip_address = request.client.host if request.client else None
    record_event(
        db=db,
        event_type="ACCOUNT_UNLOCKED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        entity_type="user",
        entity_id=str(user.id),
        outcome="SUCCESS",
        details={"unlocked_user_id": user.id, "email": user.email},
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(user)

    return user
