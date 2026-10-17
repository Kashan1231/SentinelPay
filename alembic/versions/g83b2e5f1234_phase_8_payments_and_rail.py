"""Phase 8: payments, payment_events, rail_billers, rail_records tables

Revision ID: g83b2e5f1234
Revises: a1b2c3d4e5f6
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "g83b2e5f1234"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Rail biller table ──────────────────────────────────
    op.create_table(
        "rail_billers",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column(
            "failure_mode",
            sa.Enum("OK", "DECLINE", "TIMEOUT_AFTER_PROCESS", "TIMEOUT_BEFORE_PROCESS",
                    name="failure_mode_enum"),
            nullable=False,
            server_default="OK",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rail_billers_code", "rail_billers", ["code"], unique=True)

    # ── Rail records table ─────────────────────────────────
    op.create_table(
        "rail_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rail_reference", sa.String(64), nullable=False),
        sa.Column("biller_id", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.Column(
            "status",
            sa.Enum("SETTLED", "FAILED", name="rail_record_status_enum"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["biller_id"], ["rail_billers.id"]),
    )
    op.create_index("ix_rail_records_rail_reference", "rail_records", ["rail_reference"], unique=True)
    op.create_index("ix_rail_records_biller_id", "rail_records", ["biller_id"])

    # ── Payments table ─────────────────────────────────────
    op.create_table(
        "payments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("payment_ref", sa.String(20), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("sender_account_id", sa.Integer(), nullable=False),
        sa.Column("biller_code", sa.String(64), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.Column(
            "status",
            sa.Enum("PROCESSING", "SETTLED", "FAILED", "UNKNOWN", "REVERSED",
                    "NEEDS_INVESTIGATION", name="payment_status_enum"),
            nullable=False,
            server_default="PROCESSING",
        ),
        sa.Column("rail_reference", sa.String(64), nullable=False),
        sa.Column("attempts_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["sender_account_id"], ["accounts.id"]),
    )
    op.create_index("ix_payments_payment_ref", "payments", ["payment_ref"], unique=True)
    op.create_index("ix_payments_rail_reference", "payments", ["rail_reference"], unique=True)
    op.create_index("ix_payments_user_id", "payments", ["user_id"])
    op.create_index("ix_payments_sender_account_id", "payments", ["sender_account_id"])
    op.create_index("ix_payments_biller_code", "payments", ["biller_code"])
    op.create_index("ix_payments_status", "payments", ["status"])

    # ── Payment events table ───────────────────────────────
    op.create_table(
        "payment_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("payment_id", sa.Integer(), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=True),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["payment_id"], ["payments.id"]),
    )
    op.create_index("ix_payment_events_payment_id", "payment_events", ["payment_id"])


def downgrade() -> None:
    op.drop_table("payment_events")
    op.drop_table("payments")
    op.drop_table("rail_records")
    op.drop_table("rail_billers")
    op.execute("DROP TYPE IF EXISTS payment_status_enum")
    op.execute("DROP TYPE IF EXISTS rail_record_status_enum")
    op.execute("DROP TYPE IF EXISTS failure_mode_enum")
