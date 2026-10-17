"""
SentinelPay – Sliding-window rate limiter with storage interface.

Supports:
  - Storage abstraction (RateLimitStorage) with default in-memory implementation
  - Per-IP rate limiting (auth/login, auth/register)
  - Per-user rate limiting (transactions, payments, disputes)
  - Configurable limits via application settings
  - Returns 429 Too Many Requests with Retry-After header
  - Throttled independent audit log recording (RATE_LIMITED)
"""

import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.service import record_event_independent
from app.core.config import settings


class RateLimitStorage(ABC):
    """Abstract interface for rate limiter storage."""

    @abstractmethod
    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """Check if request is rate limited. Returns (is_limited, retry_after_seconds)."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Clear all stored rate limit history."""
        pass


class InMemorySlidingWindowStorage(RateLimitStorage):
    """
    In-memory sliding window rate limiter storage.
    Note: Stored in process memory; in a multi-worker/multi-instance deployment,
    a shared storage backend like Redis should be used.
    """

    def __init__(self) -> None:
        self._history: dict[str, list[float]] = defaultdict(list)
        self._last_audit_time: dict[str, float] = {}

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window_seconds

        # Prune older entries outside sliding window
        self._history[key] = [t for t in self._history[key] if t > cutoff]

        if len(self._history[key]) >= max_requests:
            earliest = self._history[key][0]
            retry_after = max(1, int(earliest + window_seconds - now) + 1)
            return True, retry_after

        self._history[key].append(now)
        return False, 0

    def should_audit(self, key: str, throttle_seconds: int = 60) -> bool:
        """Throttle audit logging to at most once per throttle_seconds per key."""
        now = time.time()
        last = self._last_audit_time.get(key, 0.0)
        if now - last >= throttle_seconds:
            self._last_audit_time[key] = now
            return True
        return False

    def reset(self) -> None:
        self._history.clear()
        self._last_audit_time.clear()


limiter_storage = InMemorySlidingWindowStorage()


def check_rate_limit(
    request: Request,
    endpoint_key: str,
    key_type: str = "ip",
    user_id: int | None = None,
    max_requests: int = 60,
    window_seconds: int = 60,
    db: Session | None = None,
) -> None:
    """
    Verify rate limit for request.
    If RATE_LIMIT_ENABLED is False (e.g. standard tests), this is a no-op.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return

    client_ip = request.client.host if request.client else "127.0.0.1"

    if key_type == "user" and user_id is not None:
        subject_key = f"user:{user_id}"
    else:
        subject_key = f"ip:{client_ip}"

    storage_key = f"{endpoint_key}:{subject_key}"
    is_limited, retry_after = limiter_storage.is_rate_limited(
        storage_key, max_requests, window_seconds
    )

    if is_limited:
        # Throttle audit log to prevent table flooding
        if db is not None and limiter_storage.should_audit(storage_key):
            try:
                record_event_independent(
                    event_type="RATE_LIMITED",
                    actor_user_id=user_id,
                    actor_role=None,
                    entity_type="rate_limiter",
                    entity_id=storage_key,
                    outcome="DENIED",
                    details={
                        "endpoint": endpoint_key,
                        "key": storage_key,
                        "retry_after": retry_after,
                        "max_requests": max_requests,
                        "window_seconds": window_seconds,
                    },
                    ip_address=client_ip,
                    db=db,
                )
            except Exception:
                pass  # Do not block 429 response if audit write encounters issue

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
