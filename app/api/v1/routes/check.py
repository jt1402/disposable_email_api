"""
GET /v1/check?email=user@example.com
POST /v1/check  {"email": "user@example.com"}

Headers:
  X-API-Key: required — your API key
  X-Risk-Profile: optional — strict | balanced | permissive
                  Overrides the key's stored profile. Missing → key default → balanced.

Returns the 5-block CheckResponse (meta / verdict / score / signals / checks).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.api.v1.deps import require_api_key
from app.detection import engine
from app.models.check import CheckRequest, CheckResponse
from app.models.errors import invalid_email_param_error, quota_exceeded_error
from app.services import credits
from app.services.redis_client import get_redis
from app.services.unkey import VerifyResult

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
    Dev-mode keys (owner_id='dev') and enterprise keys (unlimited) skip charging.
    """
    if auth.owner_id == "dev" or auth.tier == "enterprise":
        return
    if not auth.owner_id.isdigit():
        return  # unknown owner shape; let the request through rather than falsely 402
    charged, _ = await credits.try_charge(int(auth.owner_id))
    if not charged:
        raise HTTPException(status_code=402, detail=quota_exceeded_error().model_dump())


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
        tier=auth.tier,
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
        tier=auth.tier,
        risk_profile_header=_profile_override(x_risk_profile, auth),
        request_id=_request_id(request),
    )
