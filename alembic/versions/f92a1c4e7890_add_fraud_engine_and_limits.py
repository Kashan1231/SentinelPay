"""add_fraud_engine_and_limits

Revision ID: f92a1c4e7890
Revises: e71b9f482d39
Create Date: 2026-10-13 18:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f92a1c4e7890"
down_revision: str | None = "e71b9f482d39"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Extend transaction_status_enum with 'pending_review' and 'rejected'
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE transaction_status_enum ADD VALUE IF NOT EXISTS 'pending_review'")
        op.execute("ALTER TYPE transaction_status_enum ADD VALUE IF NOT EXISTS 'rejected'")

    # 2. Create risk_level_enum & alert_status_enum if not exists
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE risk_level_enum AS ENUM ('low', 'medium', 'high');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE alert_status_enum AS ENUM ('open', 'under_review', 'resolved', 'escalated');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)

    from sqlalchemy.dialects import postgresql
    risk_level_type = postgresql.ENUM("low", "medium", "high", name="risk_level_enum", create_type=False)
    alert_status_type = postgresql.ENUM("open", "under_review", "resolved", "escalated", name="alert_status_enum", create_type=False)

    # 3. Add risk_score and risk_level to transactions
    op.add_column("transactions", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("transactions", sa.Column("risk_level", risk_level_type, nullable=True))

    # 4. Create fraud_alerts table
    op.create_table(
        "fraud_alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("transaction_id", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", risk_level_type, nullable=False),
        sa.Column("triggered_rules", sa.JSON(), nullable=False),
        sa.Column("status", alert_status_type, nullable=False),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["transaction_id"], ["transactions.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("transaction_id", name="uq_fraud_alerts_transaction_id"),
    )
    op.create_index(op.f("ix_fraud_alerts_transaction_id"), "fraud_alerts", ["transaction_id"], unique=True)
    op.create_index(op.f("ix_fraud_alerts_status"), "fraud_alerts", ["status"], unique=False)
    op.create_index(op.f("ix_fraud_alerts_reviewed_by"), "fraud_alerts", ["reviewed_by"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_fraud_alerts_reviewed_by"), table_name="fraud_alerts")
    op.drop_index(op.f("ix_fraud_alerts_status"), table_name="fraud_alerts")
    op.drop_index(op.f("ix_fraud_alerts_transaction_id"), table_name="fraud_alerts")
    op.drop_table("fraud_alerts")

    op.drop_column("transactions", "risk_level")
    op.drop_column("transactions", "risk_score")

    sa.Enum(name="alert_status_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="risk_level_enum").drop(op.get_bind(), checkfirst=True)
