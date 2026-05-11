"""
Idempotency-Key support for credit-debiting POST endpoints.

Customer flow:
  1. Customer sends `Idempotency-Key: <opaque-id>` on a /v1/check (or bulk,
     or async) POST.
  2. We hash the request body and look up `idem:{key_id}:{idem_key}` in Redis.
  3. Cache miss → run the request, store {body_hash, status, response} for 24h,
     return the response.
  4. Cache hit with same body_hash → return the stored response (no charge).
  5. Cache hit with different body_hash → 409 invalid_idempotency_key.

Cache TTL: 24 hours. Safe to retry within that window.
"""

import hashlib
import json
import logging

from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_TTL_SECONDS = 86_400
_KEY_PREFIX = "idem:"
_MAX_KEY_LEN = 255


def _normalize(idem_key: str) -> str:
    return idem_key.strip()[:_MAX_KEY_LEN]


def _body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _redis_key(api_key_id: str, idem_key: str) -> str:
    return f"{_KEY_PREFIX}{api_key_id}:{_normalize(idem_key)}"


class IdempotencyConflict(Exception):
    """Raised when the same Idempotency-Key is reused with a different body."""


async def lookup(
    redis: RedisClient,
    api_key_id: str,
    idem_key: str,
    request_body: bytes,
) -> tuple[int, dict] | None:
    """
    Return (status_code, response_body_json) if a prior identical request is
    cached. Returns None on cache miss. Raises IdempotencyConflict if the
    same idem_key was used with a different body.
    """
    if not idem_key or not api_key_id:
        return None
    raw = await redis.get(_redis_key(api_key_id, idem_key))
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except (ValueError, TypeError):
        return None
    stored_hash = record.get("body_hash", "")
    if stored_hash != _body_hash(request_body):
        raise IdempotencyConflict()
    return int(record.get("status", 200)), record.get("response", {})


async def store(
    redis: RedisClient,
    api_key_id: str,
    idem_key: str,
    request_body: bytes,
    status: int,
    response: dict,
) -> None:
    """Persist a successful response under the idem_key. Best-effort — never
    raises into the request handler."""
    if not idem_key or not api_key_id:
        return
    payload = {
        "body_hash": _body_hash(request_body),
        "status": status,
        "response": response,
    }
    try:
        await redis.setex(
            _redis_key(api_key_id, idem_key), _TTL_SECONDS, json.dumps(payload),
        )
    except Exception as exc:
        logger.debug("idempotency.store failed for %s: %s", idem_key, exc)
