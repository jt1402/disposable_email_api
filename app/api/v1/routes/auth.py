"""
Magic-link auth routes.

Flow:
  1. POST /v1/auth/signup  or  /v1/auth/login
       → body {"email": "..."}
       → always returns 202 (don't reveal account existence)
       → emails a verification link to the user

  2. User clicks link → Next.js page calls POST /v1/auth/verify
       → body {"token": "..."}
       → returns {"session_token": "...", "expires_at": "...", "user": {...}}
       → Next then stores session_token in an httpOnly cookie on its own origin

  3. Next calls any protected FastAPI route with:
       Authorization: Bearer <session_token>

  4. POST /v1/auth/logout  revokes the session.

The API deliberately does NOT set its own cookies — the frontend controls
cookie scoping (Domain/SameSite) and we stay framework-agnostic. Session
tokens are opaque bearer tokens from our perspective.
"""

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr

from app.api.v1.deps import CurrentUser
from app.core.config import get_settings
from app.models.errors import (
    ErrorDetail,
    email_send_failed_error,
    invalid_magic_link_error,
)
from app.services import auth, email, rate_limit
from app.services import keys as keys_svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / response schemas ──────────────────────────────────────────────


class EmailRequest(BaseModel):
    email: EmailStr


class VerifyRequest(BaseModel):
    token: str


class UserResponse(BaseModel):
    id: int
    email: str
    email_verified: bool
    created_at: str


class VerifyResponse(BaseModel):
    session_token: str
    expires_at: str
    user: UserResponse
    # Raw secret of the auto-provisioned default API key. Populated only on
    # the first-verification bootstrap (i.e. once per account, ever). The
    # frontend stashes it in sessionStorage and shows it on the dashboard
    # exactly once before discarding — same show-once contract as keys.create.
    default_api_key: str | None = None


class AckResponse(BaseModel):
    ok: bool = True


# ── Helpers ─────────────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()[:45]
    return request.client.host if request.client else None


def _user_payload(user: auth.UserDTO) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        email_verified=user.email_verified_at is not None,
        created_at=user.created_at.isoformat(),
    )


async def _enforce_auth_rate_limit(ip: str | None, purpose: str) -> None:
    """
    Throttle signup + login to 5 requests / IP / 15 minutes. Prevents an
    attacker from mail-bombing a target address via our magic-link endpoint.
    Fails open if Redis is down.
    """
    bucket_key = ip or "anon"
    result = await rate_limit.check_and_increment(
        scope=f"auth_{purpose}", key=bucket_key, limit=5, window_seconds=900
    )
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail=ErrorDetail(
                code="rate_limit_exceeded",
                http_status=429,
                message="Too many auth requests. Please wait 15 minutes and try again.",
                limit=result.limit,
                used=result.count,
            ).model_dump(),
        )


async def _send_magic(
    email_addr: str, purpose: str, ip: str | None
) -> None:
    """Shared path for signup + login: create-or-fetch user, issue token, email it."""
    user = await auth.get_or_create_user(email_addr)
    raw_token = await auth.issue_magic_link(user.id, purpose, ip=ip)
    settings = get_settings()
    link = f"{settings.app_base_url.rstrip('/')}/auth/verify?token={raw_token}"
    result = await email.send_magic_link(email_addr, link, purpose)
    if not result.ok:
        # Don't expose which address failed, but 502 so the client can retry.
        logger.error("Magic link send failed for purpose=%s: %s", purpose, result.error)
        raise HTTPException(status_code=502, detail=email_send_failed_error().model_dump())


# ── Routes ──────────────────────────────────────────────────────────────────


@router.post("/signup", status_code=202, response_model=AckResponse)
async def signup(body: EmailRequest, request: Request) -> AckResponse:
    """
    Start the signup flow. Always returns 202 regardless of whether the email
    was already registered — prevents account-enumeration via the signup form.
    """
    ip = _client_ip(request)
    await _enforce_auth_rate_limit(ip, "signup")
    await _send_magic(body.email, purpose="signup_verify", ip=ip)
    return AckResponse()


@router.post("/login", status_code=202, response_model=AckResponse)
async def login(body: EmailRequest, request: Request) -> AckResponse:
    """
    Passwordless login. Sends a magic link. Always returns 202 whether or not
    the email maps to an existing account (no enumeration).
    """
    ip = _client_ip(request)
    await _enforce_auth_rate_limit(ip, "login")
    await _send_magic(body.email, purpose="login", ip=ip)
    return AckResponse()


@router.post("/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest, request: Request) -> VerifyResponse:
    """
    Consume a magic-link token and issue a session. The response body carries
    the raw session token; the frontend puts it in an httpOnly cookie of its
    own choosing.
    """
    consumed = await auth.consume_magic_link(body.token)
    if consumed is None:
        raise HTTPException(status_code=400, detail=invalid_magic_link_error().model_dump())
    user, purpose = consumed

    # First-verification bootstrap: mark email verified AND auto-provision a
    # default API key. We trigger this whenever email_verified_at is still null
    # — not just on purpose=='signup_verify' — because /login on a fresh email
    # silently creates the user (anti-enumeration), and those users otherwise
    # never reach the key-provisioning path.
    default_api_key: str | None = None
    if user.email_verified_at is None:
        await auth.mark_email_verified(user.id)
        refreshed = await auth.get_user_by_id(user.id)
        if refreshed is not None:
            user = refreshed
        try:
            created = await keys_svc.create_for_user(user.id, name="Default key")
            if created is not None:
                default_api_key = created.key
        except Exception as exc:  # noqa: BLE001 — never block signup on key provisioning
            logger.error("Failed to auto-provision key for user %s: %s", user.id, exc)

    session = await auth.issue_session(
        user.id,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return VerifyResponse(
        session_token=session.token,
        expires_at=session.expires_at.isoformat(),
        user=_user_payload(user),
        default_api_key=default_api_key,
    )


@router.post("/logout", response_model=AckResponse)
async def logout(current: CurrentUser, request: Request) -> AckResponse:
    """Revoke the caller's session. The `CurrentUser` dep rejects unauth'd calls."""
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        await auth.revoke_session(authz[7:].strip())
    return AckResponse()


@router.get("/me", response_model=UserResponse)
async def me(current: CurrentUser) -> UserResponse:
    """Return the current user. Used by the Next app on hydration."""
    return _user_payload(current)
