"""
SentinelPay – Phase 10 Security Middleware.

Provides:
  - SecurityHeadersMiddleware: injects X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy, Cache-Control, HSTS (production only), and X-Request-ID.
  - RequestBodyLimitMiddleware: rejects request bodies exceeding MAX_REQUEST_BODY_BYTES with 413.
  - global_exception_handler: catches unhandled exceptions, returns a generic 500
    without leaking stack traces or SQL text, and logs details server-side.
"""

import logging
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings

logger = logging.getLogger("sentinelpay.security")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject standard security headers and a unique request ID on every response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate request ID and attach to request state for logging
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Request-ID"] = request_id

        # Cache-Control on authenticated API responses (any non-public path)
        if request.url.path not in ("/health", "/docs", "/redoc", "/openapi.json"):
            response.headers["Cache-Control"] = "no-store"

        # HSTS only in production
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        return response


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject request bodies larger than the configured maximum."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            except (ValueError, TypeError):
                pass

        return await call_next(request)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions.

    - Returns a generic 500 response without stack traces.
    - Logs the full exception server-side with a request ID.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "Unhandled exception [request_id=%s] [path=%s]: %s",
        request_id,
        request.url.path,
        str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please try again later.",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )
