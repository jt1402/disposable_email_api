"""
Test fixtures.

Uses a real Redis instance (from docker-compose) to catch normalisation
and caching edge cases that mocks would miss.
Set REDIS_URL env var or ensure docker-compose is running.
"""

import os

import pytest
import pytest_asyncio

from app.services.redis_client import RedisClient

TEST_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")  # DB 1, not DB 0


@pytest_asyncio.fixture
async def redis() -> RedisClient:
    client = RedisClient(TEST_REDIS_URL)
    assert await client.ping(), "Redis not reachable — run: docker-compose up -d redis"
    # Clean up test keys after each test
    yield client
    await client.close()
