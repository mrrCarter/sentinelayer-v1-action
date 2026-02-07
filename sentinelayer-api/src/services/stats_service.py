import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
import redis.asyncio as redis

from ..models.telemetry import TelemetryRecord
from ..schemas.stats import PublicStats

CACHE_TTL = 300  # 5 minutes


class StatsService:
    def __init__(self, db: AsyncSession, cache: redis.Redis):
        self.db = db
        self.cache = cache

    async def get_public_stats(self) -> PublicStats:
        """Get cached public stats or compute fresh."""
        cached = await self.cache.get("public_stats")
        if cached:
            return PublicStats(**json.loads(cached))

        stats = await self._compute_stats()

        await self.cache.setex(
            "public_stats",
            CACHE_TTL,
            json.dumps(stats.model_dump()),
        )

        return stats

    async def _compute_stats(self) -> PublicStats:
        """Compute aggregate stats from Tier 1 data."""
        total_runs = await self.db.scalar(
            select(func.count(TelemetryRecord.id))
        )

        total_findings = await self.db.scalar(
            select(
                func.sum(TelemetryRecord.p0_count)
                + func.sum(TelemetryRecord.p1_count)
                + func.sum(TelemetryRecord.p2_count)
                + func.sum(TelemetryRecord.p3_count)
            )
        ) or 0

        total_p0_blocked = await self.db.scalar(
            select(func.count(TelemetryRecord.id)).where(
                TelemetryRecord.gate_status == "blocked",
                TelemetryRecord.p0_count > 0,
            )
        )

        repos_protected = await self.db.scalar(
            select(func.count(func.distinct(TelemetryRecord.repo_hash)))
        )

        avg_duration = await self.db.scalar(
            select(func.avg(TelemetryRecord.duration_ms))
        ) or 0

        return PublicStats(
            total_runs=total_runs or 0,
            total_findings=int(total_findings),
            total_p0_blocked=total_p0_blocked or 0,
            repos_protected=repos_protected or 0,
            avg_duration_ms=int(avg_duration),
            top_categories=[],
        )
