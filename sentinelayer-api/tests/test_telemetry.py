import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_tier1_telemetry_no_auth(client: AsyncClient):
    """Tier 1 telemetry works without auth."""
    payload = {
        "schema_version": "1.0",
        "tier": 1,
        "run": {
            "run_id": "test-001",
            "timestamp_utc": "2026-02-04T12:00:00Z",
            "duration_ms": 5000,
        },
        "repo": {"repo_hash": "abc123"},
    }

    response = await client.post("/api/v1/telemetry", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_tier2_requires_auth(client: AsyncClient):
    """Tier 2 telemetry requires authentication."""
    payload = {
        "schema_version": "1.0",
        "tier": 2,
        "run": {
            "run_id": "test-002",
            "timestamp_utc": "2026-02-04T12:00:00Z",
            "duration_ms": 5000,
        },
        "repo": {"owner": "acme", "name": "app"},
    }

    response = await client.post("/api/v1/telemetry", json=payload)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


@pytest.mark.asyncio
async def test_duplicate_run_id_is_idempotent(client: AsyncClient):
    """Duplicate submissions return success, not error."""
    payload = {
        "schema_version": "1.0",
        "tier": 1,
        "run": {
            "run_id": "test-dupe",
            "timestamp_utc": "2026-02-04T12:00:00Z",
            "duration_ms": 5000,
        },
        "repo": {"repo_hash": "abc123"},
    }

    r1 = await client.post("/api/v1/telemetry", json=payload)
    assert r1.status_code == 200
    assert r1.json()["duplicate"] is False

    r2 = await client.post("/api/v1/telemetry", json=payload)
    assert r2.status_code == 200
    assert r2.json()["duplicate"] is True
