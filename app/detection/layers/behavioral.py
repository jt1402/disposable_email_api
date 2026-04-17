"""
Layer 4 — Behavioral Scoring (real-time)

Proprietary moat. Built automatically from API traffic.
Has no meaningful signal at launch but compounds in value over time.

Signals extracted from traffic:
- Burst: same domain queried 500+ times in 24h → likely being abused
- Cross-customer: 10+ distinct API keys querying → likely throwaway
"""

import logging
import time
from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_TTL_24H = 86_400
_BURST_THRESHOLD = 500
_CROSS_CUSTOMER_THRESHOLD = 10


@dataclass
class CheckRecord:
    name: str
    status: str
    duration_ms: float
    result: str | None = None
    probe_detail: dict | None = None


@dataclass
class BehavioralResult:
    signals: list[str] = field(default_factory=list)
    request_count_24h: int = 0
    unique_customers_24h: int = 0
    confidence_penalties: list[str] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)


async def record_query(domain: str, api_key_id: str, redis: RedisClient) -> None:
    count_key = f"behavioral:{domain}:count"
    customers_key = f"behavioral:{domain}:customers"

    pipe = redis.pipeline()
    pipe.incr(count_key)
    pipe.expire(count_key, _TTL_24H)
    pipe.pfadd(customers_key, api_key_id)
    pipe.expire(customers_key, _TTL_24H)
    await pipe.execute()


async def check(domain: str, redis: RedisClient) -> BehavioralResult:
    count_key = f"behavioral:{domain}:count"
    customers_key = f"behavioral:{domain}:customers"

    t_start = time.monotonic()
    try:
        count_raw, customer_count = await redis.execute_many(
            ("get", count_key),
            ("pfcount", customers_key),
        )
        count = int(count_raw or 0)
        unique_customers = int(customer_count or 0)
    except Exception as exc:
        logger.debug("Behavioral check failed for %s: %s", domain, exc)
        return BehavioralResult(
            confidence_penalties=["behavioral_no_history"],
            checks=[CheckRecord(
                name="behavioral_lookup",
                status="failed",
                duration_ms=(time.monotonic() - t_start) * 1000,
            )],
        )

    signals: list[str] = []
    penalties: list[str] = []

    if count >= _BURST_THRESHOLD:
        signals.append("abuse_pattern_detected")
    elif unique_customers >= _CROSS_CUSTOMER_THRESHOLD:
        signals.append("cross_customer_abuse_pattern")

    # No history at all → slight confidence penalty (Bayesian prior has no update)
    if count == 0 and unique_customers == 0:
        penalties.append("behavioral_no_history")

    return BehavioralResult(
        signals=signals,
        request_count_24h=count,
        unique_customers_24h=unique_customers,
        confidence_penalties=penalties,
        checks=[CheckRecord(
            name="behavioral_lookup",
            status="completed",
            duration_ms=(time.monotonic() - t_start) * 1000,
            result=f"{count} queries / {unique_customers} distinct customers",
        )],
    )
