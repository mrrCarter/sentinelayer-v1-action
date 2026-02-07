from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis

from ..db.connection import get_db, get_redis

router = APIRouter()


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

    Returns 503 if any dependency is down.
    """
    checks = {}

    # Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"

    # Redis
    try:
        await cache.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    all_ok = all(value == "ok" for value in checks.values())

    if not all_ok:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "One or more dependencies are unavailable",
                    "details": checks,
                    "request_id": request.state.request_id,
                }
            },
        )

    return {"status": "ready", "checks": checks}
