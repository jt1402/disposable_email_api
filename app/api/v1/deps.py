"""
FastAPI dependencies.

Injects the verified API key context into protected routes.
Unkey handles rate limiting — we just check validity and extract tier.
"""

from typing import Annotated

from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.models.errors import invalid_key_error
from app.services.unkey import VerifyResult, verify_key


async def require_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyResult:
    """
    Accepts key via:
      - X-API-Key: dc_xxxxx  (preferred)
      - Authorization: Bearer dc_xxxxx
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

    return result
