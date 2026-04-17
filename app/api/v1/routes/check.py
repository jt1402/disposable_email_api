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

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.api.v1.deps import require_api_key
from app.detection import engine
from app.models.check import CheckRequest, CheckResponse
from app.models.errors import invalid_email_param_error
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


@router.get("/check", response_model=CheckResponse, summary="Check an email address")
async def check_get(
    email: Annotated[str | None, Query(max_length=254)] = None,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    if not email:
        raise HTTPException(status_code=422, detail=invalid_email_param_error().model_dump())

    redis = get_redis()
    return await engine.check(
        email, redis,
        api_key_id=auth.key_id,
        tier=auth.tier,
        risk_profile_header=_profile_override(x_risk_profile, auth),
    )


@router.post("/check", response_model=CheckResponse, summary="Check an email address")
async def check_post(
    body: CheckRequest,
    x_risk_profile: Annotated[str | None, Header(alias="X-Risk-Profile")] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    redis = get_redis()
    return await engine.check(
        body.email, redis,
        api_key_id=auth.key_id,
        tier=auth.tier,
        risk_profile_header=_profile_override(x_risk_profile, auth),
    )
