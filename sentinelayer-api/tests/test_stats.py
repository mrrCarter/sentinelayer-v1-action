import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_public_stats_no_auth(client: AsyncClient):
    """Public stats endpoint requires no auth."""
    response = await client.get("/api/v1/public/stats")
    assert response.status_code == 200
    assert "total_runs" in response.json()
