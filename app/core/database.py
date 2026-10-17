"""
SentinelPay – SQLAlchemy engine, session factory, and declarative base.

Uses the modern SQLAlchemy 2.0 API:
  • `create_async_engine` is intentionally NOT used here — we start synchronous
    and only move to async if profiling shows we need it.
  • `get_db()` is a FastAPI dependency that yields a session and guarantees
    cleanup (commit on success, rollback on exception, close always).
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# ── Engine ────────────────────────────────────────────────
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,       # log SQL to stdout when DEBUG=true
    pool_pre_ping=True,        # reconnect stale connections automatically
)

# ── Session factory ───────────────────────────────────────
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ── Declarative base ─────────────────────────────────────
class Base(DeclarativeBase):
    """All ORM models will inherit from this class."""
    pass


# ── FastAPI dependency ────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    """Yield a transactional DB session, then clean up."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
