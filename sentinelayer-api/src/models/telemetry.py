from sqlalchemy import Column, Integer, String, Float, DateTime, Index
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone

from ..db.connection import Base


class TelemetryRecord(Base):
    """
    Telemetry record (PostgreSQL table; can be converted to a TimescaleDB hypertable if enabled).

    Tier 1 fields are always populated.
    Tier 2+ fields are nullable and only populated with consent.
    """

    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True)

    run_id = Column(String(64), unique=True, nullable=False, index=True)
    tier = Column(Integer, nullable=False)

    timestamp_utc = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    duration_ms = Column(Integer)
    gate_status = Column(String(32))
    repo_hash = Column(String(64), index=True)
    model_used = Column(String(64))
    tokens_in = Column(Integer, default=0)
    tokens_out = Column(Integer, default=0)
    cost_usd = Column(Float, default=0)
    p0_count = Column(Integer, default=0)
    p1_count = Column(Integer, default=0)
    p2_count = Column(Integer, default=0)
    p3_count = Column(Integer, default=0)

    repo_owner = Column(String(256))
    repo_name = Column(String(256))
    branch = Column(String(256))
    pr_number = Column(Integer)
    head_sha = Column(String(64))

    findings_summary = Column(JSONB)

    oidc_repo = Column(String(512))
    oidc_actor = Column(String(256))

    request_id = Column(String(64))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_telemetry_timestamp", "timestamp_utc"),
        Index("idx_telemetry_repo_hash", "repo_hash"),
        Index("idx_telemetry_gate_status", "gate_status"),
    )
