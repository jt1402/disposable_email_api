"""
FastAPI dependencies.

Two auth surfaces:
  - require_api_key  — X-API-Key / Bearer, verified against Unkey. For /v1/check.
  - require_user     — session Bearer, verified against user_sessions. For dashboard.

They are intentionally independent. A dashboard request never carries an Unkey
API key; an SDK call never carries a user session.

require_api_key additionally enforces a Redis-backed per-key burst limit
(default 600 req/min, override via Unkey meta.rate_limit_per_minute). The
limit info is stashed on request.state so the rate-limit-headers middleware
can emit X-RateLimit-* on the response.
"""

import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from app.models.errors import (
    invalid_key_error,
    invalid_session_error,
    too_many_requests_error,
)
from app.services import auth, rate_limit
from app.services.unkey import VerifyResult, verify_key

DEFAULT_KEY_RATE_LIMIT_PER_MIN = 600
RATE_LIMIT_WINDOW_SECONDS = 60


async def require_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyResult:
    """
    Accepts key via:
      - X-API-Key: dc_xxxxx  (preferred)
      - Authorization: Bearer dc_xxxxx
    Applies per-key burst rate limit on success.
    """
    raw_key: str | None = None

    if x_api_key:
        raw_key = x_api_key
    elif authorization and authorization.lower().startswith("bearer "):
        raw_key = authorization[7:].strip()

    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail=invalid_key_error().model_dump(),
        )

    result = await verify_key(raw_key)
    if not result.valid:
        raise HTTPException(
            status_code=401,
            detail=invalid_key_error().model_dump(),
        )

    # Per-key burst rate limit. Skipped in dev mode (no key_id to scope by).
    if result.key_id and result.key_id != raw_key:
        limit = result.rate_limit_per_minute or DEFAULT_KEY_RATE_LIMIT_PER_MIN
        rl = await rate_limit.check_and_increment(
            "api_key", result.key_id, limit, RATE_LIMIT_WINDOW_SECONDS,
        )
        # Compute reset = end of current fixed window. Fine resolution isn't
        # important — the customer's retry policy reads Retry-After.
        now = int(time.time())
        reset_epoch = now - (now % RATE_LIMIT_WINDOW_SECONDS) + RATE_LIMIT_WINDOW_SECONDS
        request.state.rate_limit = {
            "limit": rl.limit,
            "remaining": max(0, rl.limit - rl.count),
            "reset": reset_epoch,
        }
        if not rl.allowed:
            reset_iso = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(reset_epoch),
            )
            raise HTTPException(
                status_code=429,
                detail=too_many_requests_error(rl.limit, reset_iso).model_dump(),
                headers={
                    "Retry-After": str(reset_epoch - now),
                    "X-RateLimit-Limit": str(rl.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_epoch),
                },
            )

    return result


async def require_user(
    authorization: Annotated[str | None, Header()] = None,
) -> auth.UserDTO:
    """
    Resolve a session-bearer token (issued by /v1/auth/verify) to a user.

    The frontend stores the session token in its own httpOnly cookie and
    forwards it as `Authorization: Bearer <session_token>` on every call.
    Unknown / expired / revoked tokens → 401.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail=invalid_session_error().model_dump())
    raw_token = authorization[7:].strip()
    if not raw_token:
        raise HTTPException(status_code=401, detail=invalid_session_error().model_dump())

    user = await auth.resolve_session(raw_token)
    if user is None:
        raise HTTPException(status_code=401, detail=invalid_session_error().model_dump())
    return user


CurrentUser = Annotated[auth.UserDTO, Depends(require_user)]
