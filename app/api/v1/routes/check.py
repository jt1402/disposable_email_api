"""
GET /v1/check?email=user@example.com
POST /v1/check  {"email": "user@example.com"}

Both methods return the same CheckResponse.
GET is easier to test from a browser/curl.
POST is preferred for production use (email not logged in server access logs).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.v1.deps import require_api_key
from app.detection import engine
from app.models.check import CheckRequest, CheckResponse
from app.models.errors import invalid_email_param_error
from app.services.redis_client import get_redis
from app.services.unkey import VerifyResult

router = APIRouter()


@router.get("/check", response_model=CheckResponse, summary="Check an email address")
async def check_get(
    email: Annotated[str | None, Query(max_length=254)] = None,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail=invalid_email_param_error().model_dump())

    redis = get_redis()
    return await engine.check(email, redis, api_key_id=auth.key_id, tier=auth.tier)


@router.post("/check", response_model=CheckResponse, summary="Check an email address")
async def check_post(
    body: CheckRequest,
    auth: VerifyResult = Depends(require_api_key),
) -> CheckResponse:
    redis = get_redis()
    return await engine.check(body.email, redis, api_key_id=auth.key_id, tier=auth.tier)
