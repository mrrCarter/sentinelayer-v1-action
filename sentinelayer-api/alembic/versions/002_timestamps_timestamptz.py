"""Make telemetry timestamps timezone-aware (timestamptz).

We store timestamps in UTC. Historically the schema used `timestamp without time zone`.
This migration upgrades columns to `timestamptz` while preserving existing values by
interpreting prior values as UTC.
"""

from alembic import op
import sqlalchemy as sa

revision = "002_timestamps_timestamptz"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "telemetry",
        "timestamp_utc",
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="timestamp_utc AT TIME ZONE 'UTC'",
        nullable=False,
    )

    op.alter_column(
        "telemetry",
        "created_at",
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="created_at AT TIME ZONE 'UTC'",
    )


def downgrade():
    op.alter_column(
        "telemetry",
        "timestamp_utc",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        postgresql_using="timestamp_utc AT TIME ZONE 'UTC'",
        nullable=False,
    )

    op.alter_column(
        "telemetry",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        postgresql_using="created_at AT TIME ZONE 'UTC'",
    )

