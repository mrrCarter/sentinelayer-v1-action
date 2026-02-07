import logging
import asyncio
import time
from collections import deque
from typing import Deque, Dict
from fastapi import Depends
import redis.asyncio as redis

from ..db.connection import get_redis

logger = logging.getLogger(__name__)

_LOCAL_FALLBACK_MAX_KEYS = 5000
_local_windows: Dict[str, Deque[float]] = {}
_local_lock = asyncio.Lock()


async def _local_check(key: str, limit: int, window_seconds: int) -> bool:
    """Best-effort per-process fallback when Redis is unavailable."""
    now = time.time()
    cutoff = now - window_seconds

    async with _local_lock:
        window = _local_windows.get(key)
        if window is None:
            window = deque()
            _local_windows[key] = window

        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= limit:
            return False

        window.append(now)

        # Prevent unbounded growth if Redis is down and keys explode.
        if len(_local_windows) > _LOCAL_FALLBACK_MAX_KEYS:
            _local_windows.pop(next(iter(_local_windows)))

    return True


class RateLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def check(self, key: str, limit: int, window_seconds: int) -> bool:
        """
        Check rate limit.

        Current policy: FAIL OPEN if Redis is unavailable.
        Reason: Redis is an availability dependency; we prefer degraded rate limiting over full API outage.
        """
        try:
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds)
            results = await pipe.execute()
            return results[0] <= limit
        except Exception:
            logger.warning(
                "Rate limiter Redis error; using local fallback",
                exc_info=True,
            )
            return await _local_check(key, limit=limit, window_seconds=window_seconds)


def get_rate_limiter(cache: redis.Redis = Depends(get_redis)) -> RateLimiter:
    return RateLimiter(cache)
