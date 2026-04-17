"""
Redis client wrapper.

Provides a typed interface over redis-py's async client.
One shared connection pool for the lifetime of the application.
"""

from typing import Any

import redis.asyncio as aioredis
from redis.asyncio.client import Pipeline


class RedisClient:
    def __init__(self, url: str) -> None:
        self._client: aioredis.Redis = aioredis.from_url(
            url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )

    async def get(self, key: str) -> str | None:
        return await self._client.get(key)

    async def set(self, key: str, value: str) -> None:
        await self._client.set(key, value)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        await self._client.setex(key, ttl, value)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def incr(self, key: str) -> int:
        return await self._client.incr(key)

    async def expire(self, key: str, ttl: int) -> None:
        await self._client.expire(key, ttl)

    async def hset(self, key: str, mapping: dict[str, str]) -> None:
        await self._client.hset(key, mapping=mapping)

    async def hget(self, key: str, field: str) -> str | None:
        return await self._client.hget(key, field)

    async def hgetall(self, key: str) -> dict[str, str]:
        return await self._client.hgetall(key)

    async def pfadd(self, key: str, *values: str) -> None:
        await self._client.pfadd(key, *values)

    async def pfcount(self, key: str) -> int:
        return await self._client.pfcount(key)

    def pipeline(self) -> Pipeline:
        return self._client.pipeline()

    async def execute_many(self, *commands: tuple[str, str]) -> list[Any]:
        """Execute multiple read commands in a single pipeline round-trip."""
        pipe = self._client.pipeline(transaction=False)
        for cmd, key in commands:
            getattr(pipe, cmd)(key)
        return await pipe.execute()

    async def ping(self) -> bool:
        try:
            return await self._client.ping()
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()


_instance: RedisClient | None = None


def get_redis() -> RedisClient:
    if _instance is None:
        raise RuntimeError("Redis not initialised. Call init_redis() at startup.")
    return _instance


async def init_redis(url: str) -> RedisClient:
    global _instance
    _instance = RedisClient(url)
    return _instance


async def close_redis() -> None:
    global _instance
    if _instance:
        await _instance.close()
        _instance = None
