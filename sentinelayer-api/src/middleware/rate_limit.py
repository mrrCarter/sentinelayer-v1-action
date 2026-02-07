from fastapi import Depends, HTTPException
import redis.asyncio as redis

from ..db.connection import get_redis


class RateLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def check(self, key: str, limit: int, window_seconds: int) -> bool:
        """
        Check rate limit. FAIL CLOSED if Redis unavailable.
        """
        try:
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds)
            results = await pipe.execute()
            return results[0] <= limit
        except Exception:
            # FAIL CLOSED: If we can't check, reject
            raise HTTPException(
                status_code=503,
                detail={
                    "error": {
                        "code": "RATE_LIMITER_UNAVAILABLE",
                        "message": "Service temporarily unavailable",
                        "request_id": "unknown",
                    }
                },
            )


def get_rate_limiter(cache: redis.Redis = Depends(get_redis)) -> RateLimiter:
    return RateLimiter(cache)
