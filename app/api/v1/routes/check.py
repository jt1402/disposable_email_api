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
import json
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.api.v1.deps import CurrentUser, require_api_key
from app.detection import engine
from app.models.check import (
    AsyncCheckRequest,
    AsyncCheckResponse,
    BulkCheckRequest,
    BulkCheckResponse,
    BulkSummary,
    CheckRequest,
    CheckResponse,
    DomainCheckRequest,
)
from app.models.errors import (
    invalid_domain_param_error,
    invalid_email_param_error,
    invalid_idempotency_key_error,
    quota_exceeded_error,
)
from app.services import credits, idempotency, webhook_dispatch
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


async def _idempotency_lookup(
    auth: VerifyResult, idem_key: str | None, body: bytes,
) -> dict | None:
    """Return cached response dict if an identical prior request exists."""
    if not idem_key or not auth.key_id:
        return None
    redis = get_redis()
    try:
        hit = await idempotency.lookup(redis, auth.key_id, idem_key, body)
    except idempotency.IdempotencyConflict:
        raise HTTPException(
            status_code=409,
            detail=invalid_idempotency_key_error().model_dump(),
        )
    if hit is None:
        return None
    _, response = hit
    return response


async def _idempotency_store(
    auth: VerifyResult, idem_key: str | None, body: bytes, response: dict, status: int = 200,
) -> None:
    if not idem_key or not auth.key_id:
        return
    redis = get_redis()
    await idempotency.store(redis, auth.key_id, idem_key, body, status, response)


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
        owner_id=int(auth.owner_id) if auth.owner_id.isdigit() else None,
    )


@router.post("/check", response_model=CheckResponse, summary="Check an email address")
async def check_post(
    request: Request,
    body: CheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    raw_body = body.model_dump_json().encode("utf-8")
    cached = await _idempotency_lookup(auth, idempotency_key, raw_body)
    if cached is not None:
        return CheckResponse.model_validate(cached)

    await _charge_or_402(auth)
    redis = get_redis()
    response = await engine.check(
        body.email, redis,
        api_key_id=auth.key_id,
        risk_profile_header=_profile_override(x_risk_profile, auth),
        request_id=_request_id(request),
        owner_id=int(auth.owner_id) if auth.owner_id.isdigit() else None,
    )
    await _idempotency_store(auth, idempotency_key, raw_body, response.model_dump(mode="json"))
    return response


@router.post(
    "/check/bulk",
    response_model=BulkCheckResponse,
    summary="Check multiple email addresses (1-100 per request)",
)
async def check_bulk(
    request: Request,
    body: BulkCheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
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
    raw_body = body.model_dump_json().encode("utf-8")
    cached = await _idempotency_lookup(auth, idempotency_key, raw_body)
    if cached is not None:
        return BulkCheckResponse.model_validate(cached)

    t_start = time.monotonic()
    n = len(body.emails)
    new_balance = await _charge_n_or_402(auth, n)

    redis = get_redis()
    profile = _profile_override(x_risk_profile, auth)
    request_id_prefix = _request_id(request)
    sem = asyncio.Semaphore(_BULK_CONCURRENCY)

    owner = int(auth.owner_id) if auth.owner_id.isdigit() else None

    async def _one(idx: int, email: str) -> CheckResponse:
        async with sem:
            return await engine.check(
                email, redis,
                api_key_id=auth.key_id,
                risk_profile_header=profile,
                # Distinct request_id per row keeps audit/log lookups clean.
                request_id=f"{request_id_prefix}.{idx}" if request_id_prefix else "",
                owner_id=owner,
            )

    results = await asyncio.gather(
        *(_one(i, e) for i, e in enumerate(body.emails)),
        return_exceptions=False,
    )

    elapsed_ms = int((time.monotonic() - t_start) * 1000)
    response = BulkCheckResponse(
        items=results,
        summary=BulkSummary(
            total=n,
            credits_charged=n if auth.owner_id.isdigit() else 0,
            credits_remaining=new_balance,
            elapsed_ms=elapsed_ms,
        ),
    )
    await _idempotency_store(auth, idempotency_key, raw_body, response.model_dump(mode="json"))
    return response


@router.post(
    "/check/async",
    response_model=AsyncCheckResponse,
    status_code=202,
    summary="Async deep check — preliminary verdict now, final verdict via webhook",
)
async def check_async(
    request: Request,
    body: AsyncCheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> AsyncCheckResponse:
    """
    Two-phase verification path. Returns 202 immediately with a preliminary
    verdict from the fast/standard layers (no SMTP). The deep path (catch-all
    SMTP probing + final scoring) runs in the background and POSTs the final
    CheckResponse to your webhook URL.

    Charges 1 credit at request time, regardless of webhook outcome — the
    work is done either way. The webhook URL must be HTTPS and resolve to
    a public IP (private/loopback addresses are rejected).
    """
    ok, reason = webhook_dispatch.is_safe_webhook_url(body.webhook_url)
    if not ok:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_webhook_url", "message": f"Webhook URL rejected: {reason}"},
        )

    raw_body = body.model_dump_json().encode("utf-8")
    cached = await _idempotency_lookup(auth, idempotency_key, raw_body)
    if cached is not None:
        # Replay the prior 202 — do not re-charge and do not re-schedule the
        # webhook. Customer should treat this as the original response.
        return AsyncCheckResponse.model_validate(cached)

    await _charge_or_402(auth)

    redis = get_redis()
    profile = _profile_override(x_risk_profile, auth)
    request_id = _request_id(request) or ""
    owner = int(auth.owner_id) if auth.owner_id.isdigit() else None

    # Phase 1: synchronous standard-path check (no SMTP), fast enough to
    # return inside the 202 response.
    preliminary = await engine.check(
        body.email, redis,
        api_key_id=auth.key_id,
        risk_profile_header=profile,
        request_id=request_id,
        owner_id=owner,
    )

    # Phase 2: background deep check with catch-all probe forced on,
    # then deliver final verdict via webhook. Detached from this request.
    async def _deep_then_deliver() -> None:
        try:
            final = await engine.check(
                body.email, redis,
                api_key_id=auth.key_id,
                risk_profile_header=profile,
                request_id=f"{request_id}.async" if request_id else "",
                owner_id=owner,
                force_catchall=True,
            )
            payload = {
                "request_id": preliminary.meta.request_id,
                "event": "check.completed",
                "result": final.model_dump(mode="json"),
            }
            await webhook_dispatch.deliver(
                body.webhook_url,
                payload,
                secret=body.webhook_secret,
                request_id=preliminary.meta.request_id,
            )
        except Exception:
            logger.exception("async deep check failed (request_id=%s)", preliminary.meta.request_id)

    asyncio.create_task(_deep_then_deliver())

    response = AsyncCheckResponse(
        request_id=preliminary.meta.request_id,
        status="pending",
        preliminary=preliminary,
        webhook_url=body.webhook_url,
        # Catch-all probe budgets ~5s + DNS overhead — round figure for UX.
        estimated_completion_ms=6000,
    )
    await _idempotency_store(auth, idempotency_key, raw_body, response.model_dump(mode="json"), status=202)
    return response


@router.post(
    "/check/bulk/stream",
    summary="Bulk check (NDJSON stream — results stream as each row completes)",
    response_class=StreamingResponse,
)
async def check_bulk_stream(
    request: Request,
    body: BulkCheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> StreamingResponse:
    """
    Same as /v1/check/bulk but emits one JSON object per line as each check
    finishes — useful for very large batches (5k–100k addresses) where the
    customer wants to start processing results before the full batch is done.

    Content-Type: application/x-ndjson
    Each line is a CheckResponse. Final line is a summary object:
      {"event": "summary", "total": N, "credits_remaining": M, "elapsed_ms": K}

    Charges N credits up front, same all-or-nothing rule as /v1/check/bulk.
    Idempotency-Key is not supported here — replays would re-stream, which
    customers shouldn't depend on.
    """
    t_start = time.monotonic()
    n = len(body.emails)
    new_balance = await _charge_n_or_402(auth, n)

    redis = get_redis()
    profile = _profile_override(x_risk_profile, auth)
    request_id_prefix = _request_id(request) or ""
    owner = int(auth.owner_id) if auth.owner_id.isdigit() else None

    async def generate():
        sem = asyncio.Semaphore(_BULK_CONCURRENCY)

        async def _one(idx: int, email: str):
            async with sem:
                result = await engine.check(
                    email, redis,
                    api_key_id=auth.key_id,
                    risk_profile_header=profile,
                    request_id=f"{request_id_prefix}.{idx}" if request_id_prefix else "",
                    owner_id=owner,
                )
                return idx, result

        tasks = [asyncio.create_task(_one(i, e)) for i, e in enumerate(body.emails)]
        # as_completed lets us yield in finish-order, not input-order. The
        # customer can correlate via the `index` field in each line.
        for coro in asyncio.as_completed(tasks):
            idx, result = await coro
            line = {"index": idx, "result": result.model_dump(mode="json")}
            yield (json.dumps(line) + "\n").encode("utf-8")

        elapsed_ms = int((time.monotonic() - t_start) * 1000)
        summary = {
            "event": "summary",
            "total": n,
            "credits_charged": n if auth.owner_id.isdigit() else 0,
            "credits_remaining": new_balance,
            "elapsed_ms": elapsed_ms,
        }
        yield (json.dumps(summary) + "\n").encode("utf-8")

    return StreamingResponse(generate(), media_type="application/x-ndjson")


@router.post(
    "/check/domain",
    response_model=CheckResponse,
    summary="Check a domain only (no local part)",
)
async def check_domain(
    request: Request,
    body: DomainCheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    """
    Run the detection engine against just a domain. Identical pricing to
    /v1/check (1 credit). Use when you already have a domain and don't need
    us to syntax-validate an email — saves you from constructing a fake
    local part on the customer side.

    Internally we run the standard engine path with a neutral synthetic
    local part so no per-email signals fire. Response's `meta.email` is
    blanked so the customer never sees the synthetic probe address.
    """
    domain = body.domain.strip().lower()
    if not domain or "@" in domain or "." not in domain or len(domain) > 255:
        raise HTTPException(status_code=422, detail=invalid_domain_param_error().model_dump())

    raw_body = body.model_dump_json().encode("utf-8")
    cached = await _idempotency_lookup(auth, idempotency_key, raw_body)
    if cached is not None:
        return CheckResponse.model_validate(cached)

    await _charge_or_402(auth)
    redis = get_redis()
    # Neutral synthetic local part — short, vowel-balanced, ASCII-only.
    # None of the local-part signals fire on "probe".
    response = await engine.check(
        f"probe@{domain}", redis,
        api_key_id=auth.key_id,
        risk_profile_header=_profile_override(x_risk_profile, auth),
        request_id=_request_id(request),
        owner_id=int(auth.owner_id) if auth.owner_id.isdigit() else None,
    )
    # Blank the synthetic email — customer never asked us to validate one.
    response.meta.email = ""
    await _idempotency_store(auth, idempotency_key, raw_body, response.model_dump(mode="json"))
    return response


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
        owner_id=current.id,
    )
