"""
OAuth 2.0 routes — Google + GitHub.

GET  /v1/auth/oauth/{provider}/start     start the auth flow (302 to provider)
GET  /v1/auth/oauth/{provider}/callback  provider redirects here with code+state
POST /v1/auth/oauth/exchange             frontend swaps one-time code for session
"""

import logging
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.core.config import get_settings
from app.models.errors import ErrorDetail, invalid_session_error
from app.services import auth, oauth
from app.services import keys as keys_svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oauth", tags=["auth"])


def _client_credentials(provider_name: str) -> tuple[str, str] | None:
    """Look up the (client_id, secret) for a provider; None means unconfigured."""
    settings = get_settings()
    if provider_name == "google" and settings.google_client_id:
        return settings.google_client_id, settings.google_client_secret
    if provider_name == "github" and settings.github_client_id:
        return settings.github_client_id, settings.github_client_secret
    return None


def _redirect_uri(provider_name: str) -> str:
    settings = get_settings()
    base = settings.backend_public_url.rstrip("/")
    return f"{base}/v1/auth/oauth/{provider_name}/callback"


def _frontend_redirect(path: str, params: dict[str, str]) -> str:
    settings = get_settings()
    base = settings.app_base_url.rstrip("/")
    return f"{base}{path}?{urlencode(params)}"


@router.get("/{provider_name}/start")
async def oauth_start(provider_name: str) -> RedirectResponse:
    provider = oauth.get_provider(provider_name)
    creds = _client_credentials(provider_name)
    if provider is None or creds is None:
        raise HTTPException(
            status_code=404,
            detail=ErrorDetail(
                code="oauth_provider_unavailable",
                http_status=404,
                message=f"OAuth provider '{provider_name}' is not configured.",
            ).model_dump(),
        )
    state = await oauth.issue_state(provider_name)
    url = oauth.authorization_url(
        provider, creds[0], _redirect_uri(provider_name), state
    )
    # 302 — let the browser follow to the provider.
    return RedirectResponse(url=url, status_code=302)


@router.get("/{provider_name}/callback")
async def oauth_callback(
    provider_name: str,
    request: Request,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """
    Provider redirects the user here with ?code=...&state=...
    On error/cancel they redirect with ?error=access_denied (or similar).
    Either way we 302 the browser back to the frontend with a status param so
    the UI can render an inline message — the user is in the middle of a
    browser flow, not an API call.
    """
    if error:
        return RedirectResponse(
            url=_frontend_redirect("/login", {"oauth_error": error}),
            status_code=302,
        )

    provider = oauth.get_provider(provider_name)
    creds = _client_credentials(provider_name)
    if provider is None or creds is None:
        return RedirectResponse(
            url=_frontend_redirect("/login", {"oauth_error": "provider_unavailable"}),
            status_code=302,
        )

    expected_provider = await oauth.consume_state(state or "")
    if expected_provider != provider_name or not code:
        return RedirectResponse(
            url=_frontend_redirect("/login", {"oauth_error": "state_mismatch"}),
            status_code=302,
        )

    access_token = await oauth.exchange_code(
        provider, creds[0], creds[1], code, _redirect_uri(provider_name)
    )
    if not access_token:
        return RedirectResponse(
            url=_frontend_redirect("/login", {"oauth_error": "token_exchange_failed"}),
            status_code=302,
        )

    email_addr = await oauth.fetch_email(provider, access_token)
    if not email_addr:
        return RedirectResponse(
            url=_frontend_redirect("/login", {"oauth_error": "email_unavailable"}),
            status_code=302,
        )

    user = await auth.get_or_create_user(email_addr)

    # First-time-here bootstrap: same as /v1/auth/verify. Mark email_verified
    # because the OAuth provider already verified it; auto-provision the
    # default API key so the dashboard's WelcomeKeyBanner has something to
    # show.
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
        except Exception as exc:  # noqa: BLE001
            logger.error("OAuth default-key provision failed for user %s: %s", user.id, exc)

    fwd = request.headers.get("x-forwarded-for", "")
    client_ip = (fwd.split(",")[0].strip()[:45] if fwd else
                 (request.client.host if request.client else None))

    session = await auth.issue_session(
        user.id,
        ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )

    exchange_code_value = await oauth.issue_exchange_token(session.token, default_api_key)
    return RedirectResponse(
        url=_frontend_redirect("/auth/oauth/exchange", {"code": exchange_code_value}),
        status_code=302,
    )


class ExchangeBody(BaseModel):
    code: str


class ExchangeResponse(BaseModel):
    session_token: str
    default_api_key: str | None = None


@router.post("/exchange", response_model=ExchangeResponse)
async def oauth_exchange(body: ExchangeBody) -> ExchangeResponse:
    consumed = await oauth.consume_exchange_token(body.code)
    if consumed is None:
        raise HTTPException(status_code=400, detail=invalid_session_error().model_dump())
    session_token, default_api_key = consumed
    return ExchangeResponse(
        session_token=session_token,
        default_api_key=default_api_key,
    )
