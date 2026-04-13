"""
Layer 3 — DNS Intelligence (~50–200ms)

MX record analysis, domain age via WHOIS, MX infrastructure clustering.
All DNS calls are non-blocking (aiodns). WHOIS is synchronous but run in a thread pool.
Results are cached in Redis (TTL 24h) to avoid re-querying known domains.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiodns

from app.core.config import get_settings
from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_CACHE_TTL_DNS = 86_400       # 24 hours
_CACHE_TTL_WHOIS = 604_800    # 7 days — domain age doesn't change often
_CACHE_TTL_MX_RESULT = 86_400

REDIS_DNS_CACHE_KEY = "dns_cache:{}"
REDIS_WHOIS_CACHE_KEY = "whois_age:{}"


@dataclass
class DnsResult:
    has_mx: bool = False
    mx_hosts: list[str] = field(default_factory=list)
    mx_shared_with_disposables: bool = False
    domain_age_days: int | None = None
    signals: list[str] = field(default_factory=list)


async def _resolve_mx(domain: str, timeout: float) -> list[str]:
    resolver = aiodns.DNSResolver(timeout=timeout)
    try:
        records = await resolver.query(domain, "MX")
        return [r.host.rstrip(".").lower() for r in sorted(records, key=lambda x: x.priority)]
    except aiodns.error.DNSError:
        return []
    except Exception as exc:
        logger.debug("MX lookup failed for %s: %s", domain, exc)
        return []


async def _get_domain_age_days(domain: str, timeout: float) -> int | None:
    """Run python-whois in a thread to avoid blocking the event loop."""
    try:
        import whois  # type: ignore[import-untyped]

        w = await asyncio.wait_for(
            asyncio.to_thread(whois.whois, domain),
            timeout=timeout,
        )
        creation = w.creation_date
        if creation is None:
            return None
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime):
            return None
        # Ensure timezone-naive comparison
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        naive_creation = creation.replace(tzinfo=None) if creation.tzinfo else creation
        return max(0, (now - naive_creation).days)
    except asyncio.TimeoutError:
        logger.debug("WHOIS timeout for %s", domain)
        return None
    except Exception as exc:
        logger.debug("WHOIS failed for %s: %s", domain, exc)
        return None


async def check(domain: str, redis: RedisClient) -> DnsResult:
    settings = get_settings()

    # ── 1. Check full DNS cache first ────────────────────────────────────────
    cache_key = REDIS_DNS_CACHE_KEY.format(domain)
    cached = await redis.get(cache_key)
    if cached:
        data = json.loads(cached)
        return DnsResult(**data)

    signals: list[str] = []

    # ── 2. MX record lookup ──────────────────────────────────────────────────
    mx_hosts = await _resolve_mx(domain, settings.dns_timeout)

    if not mx_hosts:
        signals.append("no_mx_records")
        result = DnsResult(has_mx=False, signals=signals)
        await redis.setex(cache_key, _CACHE_TTL_DNS, json.dumps(result.__dict__))
        return result

    # ── 3. MX infrastructure clustering ─────────────────────────────────────
    # If multiple known-disposable domains share an MX server, flag new unknowns.
    mx_shared = False
    from app.detection.layers.blocklist import get_mx_cluster_count

    cluster_checks = await asyncio.gather(
        *[get_mx_cluster_count(mx, redis) for mx in mx_hosts],
        return_exceptions=True,
    )
    for count in cluster_checks:
        if isinstance(count, int) and count >= settings.mx_cluster_threshold:
            mx_shared = True
            signals.append("suspicious_mx_infrastructure")
            break

    # ── 4. Domain age via WHOIS ──────────────────────────────────────────────
    age_cache_key = REDIS_WHOIS_CACHE_KEY.format(domain)
    age_cached = await redis.get(age_cache_key)

    if age_cached is not None:
        domain_age_days: int | None = int(age_cached) if age_cached != "null" else None
    else:
        domain_age_days = await _get_domain_age_days(domain, settings.whois_timeout)
        await redis.setex(
            age_cache_key,
            _CACHE_TTL_WHOIS,
            str(domain_age_days) if domain_age_days is not None else "null",
        )

    # ── 5. Domain age signals ────────────────────────────────────────────────
    if domain_age_days is None:
        signals.append("domain_age_unknown")
    elif domain_age_days < 30:
        signals.append("new_domain_30d")
    elif domain_age_days < 90:
        signals.append("new_domain_90d")

    result = DnsResult(
        has_mx=True,
        mx_hosts=mx_hosts,
        mx_shared_with_disposables=mx_shared,
        domain_age_days=domain_age_days,
        signals=signals,
    )

    await redis.setex(cache_key, _CACHE_TTL_DNS, json.dumps(result.__dict__))
    return result
