"""
Layer 2 — Blocklist Matching (~2ms)

Normalised domain lookup against Redis. Subdomain stripping is critical:
sub1.throwaway.com → throwaway.com (catches all subdomain variants).
Confidence scores, not just booleans.
"""

from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

REDIS_DOMAIN_KEY = "domain:{}"
REDIS_MX_FINGERPRINT_KEY = "mx_fingerprint:{}"


@dataclass
class BlocklistResult:
    hit: bool = False
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)


def normalise_domain(domain: str) -> str:
    """
    Strip subdomains until we hit something in the blocklist or run out of labels.
    Returns the most specific matching form to use as the lookup key.

    This function returns the normalised base — the caller should try progressively
    shorter forms via strip_to_registered() for actual lookup.
    """
    return domain.lower().strip(".")


def _candidate_domains(domain: str) -> list[str]:
    """
    Returns lookup candidates from most-specific to least-specific.
    sub1.sub2.throwaway.com → [sub1.sub2.throwaway.com, sub2.throwaway.com, throwaway.com]
    Single-label domains are skipped (not valid email domains).
    """
    parts = domain.split(".")
    candidates = []
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if "." in candidate:
            candidates.append(candidate)
    return candidates


async def check(domain: str, redis: RedisClient) -> BlocklistResult:
    normalised = normalise_domain(domain)
    candidates = _candidate_domains(normalised)

    for candidate in candidates:
        key = REDIS_DOMAIN_KEY.format(candidate)
        data = await redis.hgetall(key)

        if data and data.get("disposable") == "1":
            confidence = float(data.get("confidence", "0.95"))
            return BlocklistResult(
                hit=True,
                confidence=confidence,
                signals=["known_disposable_domain"],
            )

    return BlocklistResult(hit=False)


async def get_mx_cluster_count(mx_host: str, redis: RedisClient) -> int:
    """How many known-disposable domains point to this MX server."""
    key = REDIS_MX_FINGERPRINT_KEY.format(mx_host.lower().rstrip("."))
    val = await redis.get(key)
    return int(val) if val else 0


async def increment_mx_fingerprint(mx_host: str, redis: RedisClient) -> None:
    """Called when a domain is added to the blocklist — updates MX cluster data."""
    key = REDIS_MX_FINGERPRINT_KEY.format(mx_host.lower().rstrip("."))
    await redis.incr(key)


async def store_domain(
    domain: str,
    redis: RedisClient,
    confidence: float = 0.95,
    source: str = "blocklist",
    first_seen: str = "",
    last_confirmed: str = "",
) -> None:
    """Upsert a domain entry into Redis."""
    key = REDIS_DOMAIN_KEY.format(domain.lower())
    await redis.hset(
        key,
        mapping={
            "disposable": "1",
            "confidence": str(confidence),
            "source": source,
            "first_seen": first_seen,
            "last_confirmed": last_confirmed,
        },
    )
