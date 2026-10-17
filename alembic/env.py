"""
Alembic migration environment – wired to SentinelPay's Pydantic settings.

Key design choice: the database URL is NOT duplicated in alembic.ini.
Instead, we import the app's Settings object and set it at runtime.
This guarantees that `alembic upgrade head` always uses the same URL as
the running FastAPI process.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.core.database import Base  # noqa: F401 – ensures all models are registered
import app.auth.models  # noqa: F401 – import auth models for alembic autogenerate
import app.accounts.models  # noqa: F401 – import accounts models for alembic autogenerate
import app.transactions.models  # noqa: F401 – import transactions models for alembic autogenerate
import app.fraud.models  # noqa: F401 – import fraud models for alembic autogenerate
import app.audit.models  # noqa: F401 – import audit models for alembic autogenerate
import app.payments.models  # noqa: F401
import app.rail.models  # noqa: F401
import app.recon.models  # noqa: F401
import app.disputes.models  # noqa: F401
# ── Alembic Config object ────────────────────────────────
config = context.config

# Override the (intentionally blank) sqlalchemy.url from alembic.ini
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL without connecting."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — create an engine and connect."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
