from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis
import logging

from ..db.connection import get_db, get_redis

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health")
async def health():
    """Basic liveness check."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cache: redis.Redis = Depends(get_redis),
):
    """
    Readiness check - verifies all dependencies.

    Returns 503 if the database dependency is down.

    Redis is treated as a best-effort dependency (rate limiting cache). If Redis is down, the
    service reports degraded readiness but stays in rotation.
    """
    checks = {}
    db_ok = False
    redis_ok = False

    # Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
        db_ok = True
    except Exception:
        logger.warning("Readiness DB check failed", exc_info=True)
        checks["database"] = "error"

    # Redis
    try:
        await cache.ping()
        checks["redis"] = "ok"
        redis_ok = True
    except Exception:
        logger.warning("Readiness Redis check failed", exc_info=True)
        checks["redis"] = "error"

    if not db_ok:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "One or more dependencies are unavailable",
                    "details": checks,
                    "request_id": getattr(request.state, "request_id", "unknown"),
                }
            },
        )

    status = "ready" if redis_ok else "degraded"
    return {"status": status, "checks": checks}
