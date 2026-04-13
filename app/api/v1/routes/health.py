"""
GET /health — liveness + readiness probe.

Returns 200 if the API can serve requests, 503 if a critical dependency is down.
Used by Railway health checks and the public status page.
"""

import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.redis_client import get_redis

router = APIRouter()


@router.get("/health", include_in_schema=False)
async def health() -> JSONResponse:
    t_start = time.monotonic()
    redis = get_redis()
    redis_ok = await redis.ping()
    elapsed_ms = int((time.monotonic() - t_start) * 1000)

    status = "ok" if redis_ok else "degraded"
    code = 200 if redis_ok else 503

    return JSONResponse(
        status_code=code,
        content={
            "status": status,
            "redis": "ok" if redis_ok else "error",
            "latency_ms": elapsed_ms,
        },
    )
