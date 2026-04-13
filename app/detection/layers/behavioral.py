"""
Layer 4 — Behavioral Scoring (real-time)

Proprietary moat. Built automatically from API traffic.
Has no meaningful signal at launch but compounds in value over time.

Signals extracted from traffic:
- Burst: same domain queried 500+ times in 24h → likely being abused
- Cross-customer: domain queried by many different API keys → likely throwaway
- One-shot: domain queried once, never seen again → suspicious
"""

import logging
from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_TTL_24H = 86_400
_BURST_THRESHOLD = 500       # queries to same domain in 24h
_CROSS_CUSTOMER_THRESHOLD = 10  # distinct API keys querying same domain


@dataclass
class BehavioralResult:
    signals: list[str] = field(default_factory=list)
    request_count_24h: int = 0
    unique_customers_24h: int = 0


async def record_query(domain: str, api_key_id: str, redis: RedisClient) -> None:
    """Record that this domain was queried. Called on every request."""
    count_key = f"behavioral:{domain}:count"
    customers_key = f"behavioral:{domain}:customers"

    pipe = redis.pipeline()
    pipe.incr(count_key)
    pipe.expire(count_key, _TTL_24H)
    # HyperLogLog for distinct key count — tiny memory footprint
    pipe.pfadd(customers_key, api_key_id)
    pipe.expire(customers_key, _TTL_24H)
    await pipe.execute()


async def check(domain: str, redis: RedisClient) -> BehavioralResult:
    count_key = f"behavioral:{domain}:count"
    customers_key = f"behavioral:{domain}:customers"

    try:
        count_raw, customer_count = await redis.execute_many(
            ("get", count_key),
            ("pfcount", customers_key),
        )
        count = int(count_raw or 0)
        unique_customers = int(customer_count or 0)
    except Exception as exc:
        logger.debug("Behavioral check failed for %s: %s", domain, exc)
        return BehavioralResult()

    signals: list[str] = []

    if count >= _BURST_THRESHOLD:
        signals.append("abuse_pattern_detected")
    elif unique_customers >= _CROSS_CUSTOMER_THRESHOLD:
        # Many different customers are all hitting this domain → likely a known throwaway
        # that hasn't made it to the blocklist yet
        signals.append("cross_customer_abuse_pattern")

    return BehavioralResult(
        signals=signals,
        request_count_24h=count,
        unique_customers_24h=unique_customers,
    )
