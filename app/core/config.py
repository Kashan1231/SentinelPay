"""
SentinelPay – core application settings.

All configuration is pulled from environment variables (or a .env file via
pydantic-settings).  Nothing is hardcoded; the .env.example file shows every
variable the app expects.
"""

import socket
from decimal import Decimal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralised, type-safe configuration for the entire app."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",          # silently ignore env vars we don't care about
    )

    # ── App ───────────────────────────────────────────────
    APP_NAME: str = "SentinelPay"
    DEBUG: bool = False

    # ── Database ──────────────────────────────────────────
    DATABASE_URL: str  # required – will fail fast if missing

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """
        Dynamically fallback 'db' hostname to 'localhost' when running natively
        outside Docker container where 'db' DNS host resolution fails.
        """
        if "@db:" in v or "@db/" in v:
            try:
                socket.gethostbyname("db")
            except socket.gaierror:
                # Host 'db' is unresolvable -> running natively on host OS outside Docker container
                v = v.replace("@db:", "@localhost:").replace("@db/", "@localhost/")
        return v

    # ── Security & JWT ────────────────────────────────────
    JWT_SECRET_KEY: str = "sentinelpay_super_secret_jwt_key_change_in_production_32bytes"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # ── Transaction Limits ────────────────────────────────
    SINGLE_TRANSFER_LIMIT: Decimal = Decimal("5000.00")
    DAILY_TRANSFER_LIMIT: Decimal = Decimal("10000.00")

    # ── Fraud Engine Config ───────────────────────────────
    FRAUD_LARGE_AMOUNT_THRESHOLD: Decimal = Decimal("2000.00")
    FRAUD_LARGE_AMOUNT_POINTS: int = 40
    FRAUD_HIGH_VELOCITY_COUNT: int = 3
    FRAUD_HIGH_VELOCITY_POINTS: int = 35
    FRAUD_NEW_RECIPIENT_THRESHOLD: Decimal = Decimal("500.00")
    FRAUD_NEW_RECIPIENT_POINTS: int = 30
    FRAUD_NEAR_LIMIT_PERCENT: Decimal = Decimal("0.90")
    FRAUD_NEAR_LIMIT_POINTS: int = 25
    FRAUD_NEW_ACCOUNT_DAYS: int = 30
    FRAUD_NEW_ACCOUNT_POINTS: int = 20

    # ── Payment Rail Config ──────────────────────────────────
    PAYMENT_MAX_INQUIRIES: int = 3          # max status checks before treating NOT_FOUND as failed
    PAYMENT_STUCK_AFTER_SECONDS: int = 120  # payments stuck in PROCESSING/UNKNOWN beyond this are swept

    # ── Reconciliation Config (Phase 9) ───────────────────────
    RECON_DUPLICATE_WINDOW_SECONDS: int = 300  # suspected duplicate window (seconds)

    # ── Dispute & SLA Config (Phase 9 - Part B) ───────────────
    DISPUTE_SLA_SECONDS_DUPLICATE_DEBIT: int = 86400
    DISPUTE_SLA_SECONDS_PAID_NOT_CREDITED: int = 172800
    DISPUTE_SLA_SECONDS_UNAUTHORIZED: int = 86400
    DISPUTE_SLA_SECONDS_OTHER: int = 259200
    DISPUTE_ESCALATION_GRACE_SECONDS: int = 0

    # ── Security Hardening (Phase 10) ─────────────────────────
    ENVIRONMENT: str = "development"
    DOCS_ENABLED: bool = True

    # Account Lockout
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 900  # 15 minutes

    # Rate Limiting (Disabled by default for tests; enabled in dedicated rate limit tests)
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_LOGIN_MAX: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 60
    RATE_LIMIT_REGISTER_MAX: int = 3
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = 60
    RATE_LIMIT_TRANSACTION_MAX: int = 30
    RATE_LIMIT_TRANSACTION_WINDOW_SECONDS: int = 60
    RATE_LIMIT_PAYMENT_MAX: int = 30
    RATE_LIMIT_PAYMENT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_DISPUTE_MAX: int = 15
    RATE_LIMIT_DISPUTE_WINDOW_SECONDS: int = 60

    # HTTP & Body Limits
    CORS_ORIGINS: list[str] | str = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    MAX_REQUEST_BODY_BYTES: int = 1_048_576  # 1 MB

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: list[str] | str) -> list[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


# Singleton: import `settings` everywhere, don't create new instances.
settings = Settings()

