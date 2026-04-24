"""
Simple fixed-window rate limiter over Redis.

Used to throttle auth endpoints (signup/login) by IP so attackers cannot
mail-bomb users via the magic-link trigger. Not a general-purpose limiter —
per-route limits are intentional.

Window is a fixed bucket of `window_seconds` seconds; first caller in each
bucket sets the expiry via EXPIRE. Good enough for low-volume auth routes;
swap for sliding-window if we ever need precision.
"""

from dataclasses import dataclass

from app.services.redis_client import get_redis


@dataclass
class RateLimitResult:
    allowed: bool
    count: int
    limit: int
    window_seconds: int


async def check_and_increment(
    scope: str, key: str, limit: int, window_seconds: int
) -> RateLimitResult:
    """
    Atomically INCR + EXPIRE a bucket for (scope, key). Returns the post-
    increment count. If Redis is unreachable, fails open (allowed=True) —
    the API still has Unkey on the hot path for the important limits.
    """
    redis = get_redis()
    bucket = f"rl:{scope}:{key}"
    try:
        pipe = redis.pipeline()
        pipe.incr(bucket)
        pipe.expire(bucket, window_seconds)
        count, _ = await pipe.execute()
        count = int(count)
    except Exception:
        return RateLimitResult(allowed=True, count=0, limit=limit, window_seconds=window_seconds)

    return RateLimitResult(
        allowed=count <= limit,
        count=count,
        limit=limit,
        window_seconds=window_seconds,
    )
