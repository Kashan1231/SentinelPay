"""
SentinelPay – FastAPI application entrypoint.

This file is intentionally thin: it creates the app, wires up routers, and
nothing else.  Business logic will live in the domain modules (auth/,
accounts/, transactions/, fraud/, audit/, payments/, rail/).
"""

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.accounts.router import router as accounts_router
from app.admin.overview import router as admin_overview_router
from app.audit.router import router as audit_router
from app.auth.router import admin_router as admin_users_router
from app.auth.router import router as auth_router
from app.core.config import settings
from app.core.middleware import (
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    global_exception_handler,
)
from app.disputes.router import admin_disputes_router, router as disputes_router, staff_router as staff_disputes_router
from app.fraud.router import router as fraud_router
from app.health import router as health_router
from app.payments.router import admin_router as payments_admin_router
from app.payments.router import router as payments_router
from app.rail.router import router as rail_router
from app.recon.router import router as recon_router
from app.transactions.router import router as transactions_router, staff_router as staff_transactions_router

logger = logging.getLogger("sentinelpay")

# ── Startup safety check ──────────────────────────────────────
_KNOWN_WEAK_SECRETS = {
    "sentinelpay_super_secret_jwt_key_change_in_production_32bytes",
    "changeme",
    "secret",
    "CHANGE_ME",
    "",
}

if settings.ENVIRONMENT not in ("development", "testing"):
    if (
        settings.JWT_SECRET_KEY in _KNOWN_WEAK_SECRETS
        or len(settings.JWT_SECRET_KEY) < 32
    ):
        print(
            "FATAL: JWT_SECRET_KEY is a placeholder or too short (< 32 chars). "
            "Set a strong secret before running in a non-development environment.",
            file=sys.stderr,
        )
        sys.exit(1)

# ── App creation ──────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    description="Simulated fintech transaction platform with fraud detection.",
    version="0.1.0",
    docs_url="/docs" if settings.DOCS_ENABLED else None,
    redoc_url="/redoc" if settings.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if settings.DOCS_ENABLED else None,
)

# ── Middleware (order matters: outermost first) ────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestBodyLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Global exception handler ─────────────────────────────────
app.add_exception_handler(Exception, global_exception_handler)

# ── Routers ───────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(admin_users_router)
app.include_router(accounts_router)
app.include_router(transactions_router)
app.include_router(staff_transactions_router)
app.include_router(admin_overview_router)
app.include_router(fraud_router)
app.include_router(audit_router)
app.include_router(payments_router)
app.include_router(payments_admin_router)
app.include_router(rail_router)
app.include_router(recon_router)
app.include_router(disputes_router)
app.include_router(staff_disputes_router)
app.include_router(admin_disputes_router)
