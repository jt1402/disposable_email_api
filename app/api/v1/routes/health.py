"""
GET /health — binary liveness probe (used by Railway / load balancers).
GET /v1/status — detailed component health for customer-visible status pages.

/health returns 200 if the process is up and Redis is reachable; 503 otherwise.
/v1/status always returns 200 with per-component degradation flags so a
customer can read it to diagnose their integration.
"""

import asyncio
import time

import aiodns
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.services import db
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


async def _check_postgres(timeout: float = 2.0) -> bool:
    try:
        async with db.get_session() as s:
            await asyncio.wait_for(s.execute(text("SELECT 1")), timeout=timeout)
        return True
    except Exception:
        return False


async def _check_dns(timeout: float = 2.0) -> bool:
    try:
        resolver = aiodns.DNSResolver(timeout=timeout, tries=1)
        await asyncio.wait_for(resolver.query("google.com", "A"), timeout=timeout)
        return True
    except Exception:
        return False


@router.get("/v1/status")
async def status() -> dict:
    """
    Detailed component health for diagnosing integration issues. Always
    returns 200 — read individual `*.status` fields for per-component state.
    """
    t_start = time.monotonic()
    redis = get_redis()
    redis_ok, pg_ok, dns_ok = await asyncio.gather(
        redis.ping(),
        _check_postgres(),
        _check_dns(),
    )
    overall = "ok" if (redis_ok and pg_ok and dns_ok) else "degraded"
    return {
        "status": overall,
        "components": {
            "redis": "ok" if redis_ok else "degraded",
            "postgres": "ok" if pg_ok else "degraded",
            "dns": "ok" if dns_ok else "degraded",
        },
        "latency_ms": int((time.monotonic() - t_start) * 1000),
    }
