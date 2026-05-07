"""
GET /v1/check?email=user@example.com
POST /v1/check  {"email": "user@example.com"}
POST /v1/check/bulk  {"emails": [...]}   (1-100 per request)

Headers:
  X-API-Key: required — your API key
  X-Risk-Profile: optional — strict | balanced | permissive
                  Overrides the key's stored profile. Missing → key default → balanced.

Returns the 5-block CheckResponse (meta / verdict / score / signals / checks).
"""

import asyncio
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.api.v1.deps import CurrentUser, require_api_key
from app.detection import engine
from app.models.check import (
    BulkCheckRequest,
    BulkCheckResponse,
    BulkSummary,
    CheckRequest,
    CheckResponse,
)
from app.models.errors import invalid_email_param_error, quota_exceeded_error
from app.services import credits
from app.services.redis_client import get_redis
from app.services.unkey import VerifyResult

# Cap concurrent engine tasks per bulk request — protects DNS/SMTP infrastructure
# while still cutting wall time vs serial. 10 is a safe default with our
# resolver pool.
_BULK_CONCURRENCY = 10

logger = logging.getLogger(__name__)

router = APIRouter()


def _profile_override(header_value: str | None, auth: VerifyResult) -> str | None:
    """Header wins; else Unkey-stored default; else None (engine falls back to settings)."""
    if header_value:
        return header_value
    if auth.risk_profile:
        return auth.risk_profile
    return None


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "") or ""


async def _charge_or_402(auth: VerifyResult) -> None:
    """
    Deduct one credit from the key owner's balance, or raise 402.
    Dev-mode keys (owner_id='dev') skip charging.
    """
    if auth.owner_id == "dev":
        return
    if not auth.owner_id.isdigit():
        # We can't map this key back to a user — let the request through
        # rather than falsely 402, but loud-log it so a misconfigured Unkey
        # response (e.g. missing identity.externalId) doesn't silently grant
        # free checks like it did before the v2 identity-nesting fix.
        logger.warning(
            "Skipping credit charge: owner_id=%r is not numeric (key=%s).",
            auth.owner_id, auth.key_id,
        )
        return
    charged, _ = await credits.try_charge(int(auth.owner_id))
    if not charged:
        raise HTTPException(status_code=402, detail=quota_exceeded_error().model_dump())


async def _charge_n_or_402(auth: VerifyResult, n: int) -> int:
    """
    Atomically charge N credits or raise 402. Returns the new balance.
    Dev-mode + non-numeric owner_id skip charging (mirrors single-charge path).
    """
    if auth.owner_id == "dev":
        return 0
    if not auth.owner_id.isdigit():
        logger.warning(
            "Skipping bulk credit charge: owner_id=%r is not numeric (key=%s).",
            auth.owner_id, auth.key_id,
        )
        return 0
    charged, balance = await credits.try_charge_n(int(auth.owner_id), n)
    if not charged:
        raise HTTPException(status_code=402, detail=quota_exceeded_error().model_dump())
    return balance


@router.get("/check", response_model=CheckResponse, summary="Check an email address")
async def check_get(
    request: Request,
    email: Annotated[str | None, Query(max_length=254)] = None,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    if not email:
        raise HTTPException(status_code=422, detail=invalid_email_param_error().model_dump())

    await _charge_or_402(auth)
    redis = get_redis()
    return await engine.check(
        email, redis,
        api_key_id=auth.key_id,
        risk_profile_header=_profile_override(x_risk_profile, auth),
        request_id=_request_id(request),
    )


@router.post("/check", response_model=CheckResponse, summary="Check an email address")
async def check_post(
    request: Request,
    body: CheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    await _charge_or_402(auth)
    redis = get_redis()
    return await engine.check(
        body.email, redis,
        api_key_id=auth.key_id,
        risk_profile_header=_profile_override(x_risk_profile, auth),
        request_id=_request_id(request),
    )


@router.post(
    "/check/bulk",
    response_model=BulkCheckResponse,
    summary="Check multiple email addresses (1-100 per request)",
)
async def check_bulk(
    request: Request,
    body: BulkCheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> BulkCheckResponse:
    """
    Bulk verification path. Charges N credits up front (all-or-nothing —
    if balance < N, the request 402s without partial debit). Internally
    runs the same engine path per email with a concurrency cap so a 100-row
    batch finishes in roughly 10× a single check rather than 100×.

    Each item in `items` is a full CheckResponse, in the same order as the
    input. Invalid syntax produces a CheckResponse with recommendation=block,
    not an error — bulk never fails individual rows separately.
    """
    t_start = time.monotonic()
    n = len(body.emails)
    new_balance = await _charge_n_or_402(auth, n)

    redis = get_redis()
    profile = _profile_override(x_risk_profile, auth)
    request_id_prefix = _request_id(request)
    sem = asyncio.Semaphore(_BULK_CONCURRENCY)

    async def _one(idx: int, email: str) -> CheckResponse:
        async with sem:
            return await engine.check(
                email, redis,
                api_key_id=auth.key_id,
                risk_profile_header=profile,
                # Distinct request_id per row keeps audit/log lookups clean.
                request_id=f"{request_id_prefix}.{idx}" if request_id_prefix else "",
            )

    results = await asyncio.gather(
        *(_one(i, e) for i, e in enumerate(body.emails)),
        return_exceptions=False,
    )

    elapsed_ms = int((time.monotonic() - t_start) * 1000)
    return BulkCheckResponse(
        items=results,
        summary=BulkSummary(
            total=n,
            credits_charged=n if auth.owner_id.isdigit() else 0,
            credits_remaining=new_balance,
            elapsed_ms=elapsed_ms,
        ),
    )


@router.post(
    "/check/preview",
    response_model=CheckResponse,
    include_in_schema=False,
    summary="Dashboard playground — session-authed, no API key required",
)
async def check_preview(
    request: Request,
    body: CheckRequest,
    current: CurrentUser,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
) -> CheckResponse:
    """
    Dashboard-only variant of /v1/check. Authenticated via the session bearer
    rather than X-API-Key, and charges the user's credit balance directly.
    Results are tagged api_key_id='playground:{user_id}' so they never land in
    the customer-facing usage aggregates.
    """
    charged, _ = await credits.try_charge(current.id)
    if not charged:
        raise HTTPException(status_code=402, detail=quota_exceeded_error().model_dump())
    redis = get_redis()
    return await engine.check(
        body.email, redis,
        api_key_id=f"playground:{current.id}",
        risk_profile_header=x_risk_profile,
        request_id=_request_id(request),
    )
