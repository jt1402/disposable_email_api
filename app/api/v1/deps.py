"""
FastAPI dependencies.

Two auth surfaces:
  - require_api_key  — X-API-Key / Bearer, verified against Unkey. For /v1/check.
  - require_user     — session Bearer, verified against user_sessions. For dashboard.

They are intentionally independent. A dashboard request never carries an Unkey
API key; an SDK call never carries a user session.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException

from app.models.errors import invalid_key_error, invalid_session_error
from app.services import auth
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
