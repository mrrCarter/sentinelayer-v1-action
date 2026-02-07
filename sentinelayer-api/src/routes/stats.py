from fastapi import APIRouter, Depends

from ..services.stats_service import StatsService
from ..schemas.stats import PublicStats
from ..db.connection import get_timescale_db, get_redis
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

router = APIRouter()


def get_stats_service(
    db: AsyncSession = Depends(get_timescale_db),
    cache: redis.Redis = Depends(get_redis),
) -> StatsService:
    return StatsService(db, cache)


@router.get("/public/stats", response_model=PublicStats)
async def get_public_stats(
    stats_service: StatsService = Depends(get_stats_service),
):
    """
    Get anonymous aggregate statistics.

    Cached for 5 minutes. No auth required.
    """
    return await stats_service.get_public_stats()
