import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from src.main import app
from src.routes.telemetry import get_telemetry_service
from src.middleware.rate_limit import get_rate_limiter
from src.routes.stats import get_stats_service
from src.services.telemetry_service import IngestResult
from src.schemas.stats import PublicStats

pytest_plugins = ["pytest_asyncio"]


class DummyRateLimiter:
    async def check(self, key: str, limit: int, window_seconds: int) -> bool:
        return True


class DummyTelemetryService:
    def __init__(self):
        self._run_ids = set()

    async def ingest(self, payload, claims, request_id):
        duplicate = payload.run.run_id in self._run_ids
        self._run_ids.add(payload.run.run_id)
        return IngestResult(success=True, duplicate=duplicate, record_id=1)


class DummyStatsService:
    async def get_public_stats(self) -> PublicStats:
        return PublicStats(
            total_runs=0,
            total_findings=0,
            total_p0_blocked=0,
            repos_protected=0,
            avg_duration_ms=0,
            top_categories=[],
        )


@pytest_asyncio.fixture
async def client():
    telemetry_service = DummyTelemetryService()
    rate_limiter = DummyRateLimiter()
    stats_service = DummyStatsService()

    app.dependency_overrides[get_telemetry_service] = lambda: telemetry_service
    app.dependency_overrides[get_rate_limiter] = lambda: rate_limiter
    app.dependency_overrides[get_stats_service] = lambda: stats_service

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client

    app.dependency_overrides.clear()
