"""
Layer 2 — Blocklist + Trusted-Provider Matching (~2ms)

Two-way check: known disposable (risk signal) OR known legitimate provider
(trust signal). Subdomain stripping on the lookup so sub.throwaway.com matches
throwaway.com.

High-confidence blocklist hits (>0.95) emit a hard disqualifier.
Medium-confidence hits (0.70–0.95) emit a strong signal that can still be
outweighed by enough trust signals.
"""

from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

REDIS_DOMAIN_KEY = "domain:{}"
REDIS_MX_FINGERPRINT_KEY = "mx_fingerprint:{}"

# Major mail providers — automatic trust signal.
TRUSTED_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "aol.com",
    "protonmail.com", "proton.me", "pm.me",
    "fastmail.com", "fastmail.fm",
    "zoho.com", "zohomail.com",
    "tutanota.com", "tuta.io",
    "yandex.com", "yandex.ru",
    "mail.com", "gmx.com", "gmx.net",
})

HIGH_CONFIDENCE_THRESHOLD = 0.95


@dataclass
class BlocklistResult:
    hit: bool = False
    confidence: float = 0.0
    is_trusted_provider: bool = False
    signals: list[str] = field(default_factory=list)


def normalise_domain(domain: str) -> str:
    return domain.lower().strip(".")


def _candidate_domains(domain: str) -> list[str]:
    """Most-specific to least-specific; single-label domains are skipped."""
    parts = domain.split(".")
    candidates = []
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if "." in candidate:
            candidates.append(candidate)
    return candidates


async def check(domain: str, redis: RedisClient) -> BlocklistResult:
    normalised = normalise_domain(domain)

    # ── Trusted-provider fast exit ───────────────────────────────────────────
    if normalised in TRUSTED_PROVIDERS:
        return BlocklistResult(
            hit=False,
            is_trusted_provider=True,
            signals=["known_legitimate_provider"],
        )

    # ── Blocklist (progressive subdomain stripping) ─────────────────────────
    for candidate in _candidate_domains(normalised):
        key = REDIS_DOMAIN_KEY.format(candidate)
        data = await redis.hgetall(key)

        if data and data.get("disposable") == "1":
            try:
                confidence = float(data.get("confidence", "0.95"))
            except ValueError:
                confidence = 0.95

            if confidence >= HIGH_CONFIDENCE_THRESHOLD:
                signal = "known_disposable_domain_high_confidence"
            else:
                signal = "known_disposable_domain"

            return BlocklistResult(
                hit=True,
                confidence=confidence,
                signals=[signal],
            )

    return BlocklistResult(hit=False)


async def get_mx_cluster_count(mx_host: str, redis: RedisClient) -> int:
    key = REDIS_MX_FINGERPRINT_KEY.format(mx_host.lower().rstrip("."))
    val = await redis.get(key)
    return int(val) if val else 0


async def increment_mx_fingerprint(mx_host: str, redis: RedisClient) -> None:
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
