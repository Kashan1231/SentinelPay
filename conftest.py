"""
Root conftest for SentinelPay test suite.
Configures test database engine against PostgreSQL on a dedicated test database (sentinelpay_test).
Includes safety guards to prevent accidental TRUNCATE against production or development databases.
"""

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

import app.audit.models  # noqa: F401
import app.payments.models  # noqa: F401
import app.rail.models  # noqa: F401
import app.recon.models  # noqa: F401
import app.disputes.models  # noqa: F401
from app.core.database import Base, get_db
from app.main import app

# Dedicated test database URL
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://sentinelpay:changeme@localhost:5432/sentinelpay_test",
)


def ensure_test_database_exists(db_url_str: str) -> None:
    """Connect to default database and create test database if it does not exist."""
    url = make_url(db_url_str)
    target_db = url.database

    if not target_db:
        return

    # Connect to the maintenance/default db (sentinelpay or postgres)
    admin_url = url.set(database="sentinelpay")
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

    try:
        with admin_engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
                {"dbname": target_db},
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{target_db}"'))
    except Exception:
        # Fallback to 'postgres' maintenance database if 'sentinelpay' db isn't accessible
        try:
            admin_url_postgres = url.set(database="postgres")
            admin_engine_pg = create_engine(admin_url_postgres, isolation_level="AUTOCOMMIT")
            with admin_engine_pg.connect() as conn:
                exists = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
                    {"dbname": target_db},
                ).scalar()
                if not exists:
                    conn.execute(text(f'CREATE DATABASE "{target_db}"'))
            admin_engine_pg.dispose()
        except Exception:
            pass
    finally:
        admin_engine.dispose()


test_engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
TestSession = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
from app.core.database import SessionLocal
SessionLocal.configure(bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def initialize_database() -> Generator[None, None, None]:
    """Ensure test database exists, then create all tables in PostgreSQL at session start."""
    ensure_test_database_exists(TEST_DATABASE_URL)
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    with test_engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_logs is an append-only table. UPDATE and DELETE operations are prohibited.';
                END;
                $$ LANGUAGE plpgsql;

                DROP TRIGGER IF EXISTS audit_logs_prevent_update_delete ON audit_logs;
                CREATE TRIGGER audit_logs_prevent_update_delete
                BEFORE UPDATE OR DELETE ON audit_logs
                FOR EACH ROW
                EXECUTE FUNCTION prevent_audit_log_modification();
                """
            )
        )
    yield


@pytest.fixture(autouse=True)
def clean_tables_between_tests() -> Generator[None, None, None]:
    """
    Clean table rows before each test to guarantee complete test isolation.
    CRITICAL SAFETY GUARD: Refuses to TRUNCATE unless database name ends with '_test'.
    """
    db_name = test_engine.url.database or ""
    if not db_name.endswith("_test"):
        raise RuntimeError(
            f"CRITICAL SAFETY VIOLATION: Refusing to TRUNCATE database '{db_name}'. "
            "Tests must strictly run against a database ending with '_test' to protect development data."
        )

    with test_engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE dispute_refunds, dispute_events, disputes, reconciliation_exceptions, reconciliation_runs, audit_logs, payment_events, payments, rail_records, rail_billers, fraud_alerts, idempotency_keys, transactions, accounts, users RESTART IDENTITY CASCADE;"))
    yield
    with test_engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE dispute_refunds, dispute_events, disputes, reconciliation_exceptions, reconciliation_runs, audit_logs, payment_events, payments, rail_records, rail_billers, fraud_alerts, idempotency_keys, transactions, accounts, users RESTART IDENTITY CASCADE;"))
    # Dispose connection pool after each test to release any lingering Postgres
    # connections/locks left by concurrent tests (e.g. ThreadPoolExecutor threads).
    test_engine.dispose()


def override_get_db() -> Generator[Session, None, None]:
    """Provide a database session connected to the test database."""
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)
