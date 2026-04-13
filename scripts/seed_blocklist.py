"""
Seed the Redis blocklist from the disposable-email-domains GitHub list.

Usage:
    python scripts/seed_blocklist.py

Downloads the raw list from GitHub and loads all domains into Redis.
Run once on first deploy, then use refresh_blocklist.py for incremental updates.
"""

import asyncio
import sys
from datetime import date

import httpx

sys.path.insert(0, ".")

from app.core.config import get_settings
from app.detection.layers.blocklist import store_domain
from app.services.redis_client import RedisClient

# The canonical open-source disposable email domain list
SOURCE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)


async def seed(redis_url: str | None = None) -> None:
    settings = get_settings()
    url = redis_url or settings.redis_url

    print(f"Connecting to Redis at {url}...")
    redis = RedisClient(url)

    if not await redis.ping():
        print("ERROR: Cannot connect to Redis. Is it running?")
        sys.exit(1)

    print(f"Downloading blocklist from {SOURCE_URL}...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(SOURCE_URL)
        resp.raise_for_status()

    domains = [
        line.strip().lower()
        for line in resp.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    print(f"Found {len(domains)} domains to load...")

    today = date.today().isoformat()
    batch_size = 200
    loaded = 0

    for i in range(0, len(domains), batch_size):
        batch = domains[i : i + batch_size]
        # Use a single pipeline per batch — one connection, many commands
        pipe = redis.pipeline()
        for domain in batch:
            key = f"domain:{domain}"
            pipe.hset(key, mapping={
                "disposable": "1",
                "confidence": "0.95",
                "source": "github_list",
                "first_seen": today,
                "last_confirmed": today,
            })
        await pipe.execute()
        loaded += len(batch)
        print(f"  {loaded}/{len(domains)} loaded...", end="\r")

    print(f"\nDone. {loaded} disposable domains loaded into Redis.")
    await redis.close()


if __name__ == "__main__":
    asyncio.run(seed())
