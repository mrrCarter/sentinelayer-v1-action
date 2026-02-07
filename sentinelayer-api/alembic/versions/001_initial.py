"""Initial schema (PostgreSQL)

This migration intentionally avoids TimescaleDB-specific functions so the stack can run on
vanilla RDS PostgreSQL without extra extension enablement.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Alembic revision identifiers.
revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "telemetry",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(64), unique=True, nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("timestamp_utc", sa.DateTime(), nullable=False),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("gate_status", sa.String(32)),
        sa.Column("repo_hash", sa.String(64)),
        sa.Column("model_used", sa.String(64)),
        sa.Column("tokens_in", sa.Integer(), server_default="0"),
        sa.Column("tokens_out", sa.Integer(), server_default="0"),
        sa.Column("cost_usd", sa.Float(), server_default="0"),
        sa.Column("p0_count", sa.Integer(), server_default="0"),
        sa.Column("p1_count", sa.Integer(), server_default="0"),
        sa.Column("p2_count", sa.Integer(), server_default="0"),
        sa.Column("p3_count", sa.Integer(), server_default="0"),
        sa.Column("repo_owner", sa.String(256)),
        sa.Column("repo_name", sa.String(256)),
        sa.Column("branch", sa.String(256)),
        sa.Column("pr_number", sa.Integer()),
        sa.Column("head_sha", sa.String(64)),
        sa.Column("findings_summary", postgresql.JSONB()),
        sa.Column("oidc_repo", sa.String(512)),
        sa.Column("oidc_actor", sa.String(256)),
        sa.Column("request_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime()),
    )

    # Indices to match the ORM model.
    op.create_index("idx_telemetry_timestamp", "telemetry", ["timestamp_utc"])
    op.create_index("idx_telemetry_repo_hash", "telemetry", ["repo_hash"])
    op.create_index("idx_telemetry_gate_status", "telemetry", ["gate_status"])


def downgrade():
    op.drop_table("telemetry")
