"""
Per-user custom allow / block lists.

Each user has two domain sets stored in Redis:
  custom:allow:{user_id}  → forces recommendation=allow,  score=0   on match
  custom:block:{user_id}  → forces recommendation=block,  score=100 on match

Lists are scoped to the user, not the API key — every key the user owns
shares the same overrides. Engine consults these before any detection
layer runs, so matches are O(1) Redis lookups (~1ms) and bypass the
DNS/WHOIS path entirely.
"""

from app.services.redis_client import RedisClient

ALLOW = "allow"
BLOCK = "block"
REVIEWED = "reviewed"
_ALLOWED_KINDS: frozenset[str] = frozenset({ALLOW, BLOCK, REVIEWED})

# Verdict-altering kinds — only allow/block change the engine's verdict.
# `reviewed` is a UI-only "I've decided about this domain, hide from the
# pending queue" marker.
_VERDICT_KINDS: frozenset[str] = frozenset({ALLOW, BLOCK})


def _key(kind: str, user_id: int) -> str:
    if kind == REVIEWED:
        # Reviewed keys live under their own namespace — they don't change
        # any verdict, so keeping them off the `custom:*` prefix avoids
        # accidental dispatch into the engine's lookup path.
        return f"reviewed:{user_id}"
    return f"custom:{kind}:{user_id}"


def _normalize(domain: str) -> str:
    """Lowercase + strip — domain matching is case-insensitive."""
    return domain.strip().lower()


async def list_domains(redis: RedisClient, user_id: int, kind: str) -> list[str]:
    if kind not in _ALLOWED_KINDS:
        raise ValueError(f"Invalid list kind: {kind}")
    members = await redis.smembers(_key(kind, user_id))
    return sorted(set(members))


async def add_domain(redis: RedisClient, user_id: int, kind: str, domain: str) -> bool:
    if kind not in _ALLOWED_KINDS:
        raise ValueError(f"Invalid list kind: {kind}")
    d = _normalize(domain)
    if not d:
        return False
    added = await redis.sadd(_key(kind, user_id), d)
    return added > 0


async def remove_domain(redis: RedisClient, user_id: int, kind: str, domain: str) -> bool:
    if kind not in _ALLOWED_KINDS:
        raise ValueError(f"Invalid list kind: {kind}")
    d = _normalize(domain)
    if not d:
        return False
    removed = await redis.srem(_key(kind, user_id), d)
    return removed > 0


async def lookup(redis: RedisClient, user_id: int, domain: str) -> str | None:
    """
    Return 'allow', 'block', or None depending on which list the domain hits.
    Allow takes precedence so users can carve trusted domains out of an
    otherwise-blocked range. Reviewed-only domains do not change the verdict
    and are intentionally not consulted here.
    """
    d = _normalize(domain)
    if not d:
        return None
    if await redis.sismember(_key(ALLOW, user_id), d):
        return ALLOW
    if await redis.sismember(_key(BLOCK, user_id), d):
        return BLOCK
    return None
