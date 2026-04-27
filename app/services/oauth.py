"""
OAuth 2.0 (authorization-code flow) for Google + GitHub.

Flow:
  1. /v1/auth/oauth/{provider}/start   — generate `state`, redirect to provider
  2. provider redirects back to /v1/auth/oauth/{provider}/callback
     — validate state, exchange code for access_token, fetch verified email
  3. find-or-create User; first-time verifiers get the default-key bootstrap
  4. issue a short-lived `exchange_token` keyed in Redis to (session_token,
     default_api_key)
  5. redirect to frontend `/auth/oauth/exchange?code=<exchange_token>`
  6. frontend POSTs the exchange_token back to /v1/auth/oauth/exchange and
     receives the session token + default key — same hand-off shape as
     /v1/auth/verify so the existing setSession + WelcomeKeyBanner pipes
     through unchanged.

State + exchange tokens live in Redis only (10 min / 5 min TTL respectively).
We never persist OAuth access tokens — we just need the email once, then we
forget the provider connection.
"""

import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    name: str
    auth_url: str
    token_url: str
    userinfo_url: str
    scope: str


PROVIDERS: dict[str, ProviderConfig] = {
    "google": ProviderConfig(
        name="google",
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        scope="openid email profile",
    ),
    "github": ProviderConfig(
        name="github",
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        scope="read:user user:email",
    ),
}


_STATE_PREFIX = "oauth:state:"
_STATE_TTL = 600  # 10 minutes
_EXCHANGE_PREFIX = "oauth:exchange:"
_EXCHANGE_TTL = 300  # 5 minutes


def get_provider(name: str) -> ProviderConfig | None:
    return PROVIDERS.get(name)


def authorization_url(
    provider: ProviderConfig, client_id: str, redirect_uri: str, state: str
) -> str:
    qs = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": provider.scope,
        "state": state,
        "access_type": "online",
    }
    return f"{provider.auth_url}?{urlencode(qs)}"


async def issue_state(provider_name: str) -> str:
    """Generate a random state token, store {state -> provider} for callback validation."""
    state = secrets.token_urlsafe(32)
    redis = get_redis()
    await redis.setex(f"{_STATE_PREFIX}{state}", _STATE_TTL, provider_name)
    return state


async def consume_state(state: str) -> str | None:
    """Return the provider that issued this state, or None if unknown/expired. Single-use."""
    if not state:
        return None
    redis = get_redis()
    key = f"{_STATE_PREFIX}{state}"
    provider_name = await redis.get(key)
    if provider_name:
        await redis.delete(key)
    return provider_name


async def exchange_code(
    provider: ProviderConfig,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> str | None:
    """POST the auth code to the provider's token endpoint. Returns access_token or None."""
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    headers = {"Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(provider.token_url, data=payload, headers=headers)
        if resp.status_code != 200:
            logger.error("OAuth %s token exchange returned %s: %s",
                         provider.name, resp.status_code, resp.text)
            return None
        data = resp.json()
    except (httpx.RequestError, json.JSONDecodeError) as exc:
        logger.error("OAuth %s token exchange failed: %s", provider.name, exc)
        return None
    return data.get("access_token")


async def fetch_email(
    provider: ProviderConfig, access_token: str
) -> str | None:
    """
    Resolve the verified primary email for the access token.

    Google: /userinfo always returns `email` + `email_verified`.
    GitHub: /user often hides email; /user/emails lists all addresses with
      `primary` and `verified` flags. We pick the verified primary.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(provider.userinfo_url, headers=headers)
            if resp.status_code != 200:
                logger.error("OAuth %s userinfo returned %s",
                             provider.name, resp.status_code)
                return None
            data: Any = resp.json()

            if provider.name == "google":
                if not data.get("email_verified"):
                    return None
                return (data.get("email") or "").strip().lower() or None

            if provider.name == "github":
                # Always pull the email list — the /user payload's email field
                # may be null for users with private email settings.
                emails_resp = await client.get(
                    "https://api.github.com/user/emails", headers=headers
                )
                if emails_resp.status_code != 200:
                    return None
                for entry in emails_resp.json():
                    if entry.get("primary") and entry.get("verified"):
                        return (entry.get("email") or "").strip().lower() or None
                return None
    except (httpx.RequestError, json.JSONDecodeError) as exc:
        logger.error("OAuth %s userinfo fetch failed: %s", provider.name, exc)
        return None

    return None


async def issue_exchange_token(session_token: str, default_api_key: str | None) -> str:
    """
    Generate a one-time code that the frontend will POST back to swap for the
    session bearer + default key. Held in Redis for 5 minutes; single use.
    """
    code = secrets.token_urlsafe(32)
    redis = get_redis()
    payload = json.dumps({"session_token": session_token, "default_api_key": default_api_key})
    await redis.setex(f"{_EXCHANGE_PREFIX}{code}", _EXCHANGE_TTL, payload)
    return code


async def consume_exchange_token(code: str) -> tuple[str, str | None] | None:
    """Return (session_token, default_api_key) and delete; None if unknown/expired."""
    if not code:
        return None
    redis = get_redis()
    key = f"{_EXCHANGE_PREFIX}{code}"
    raw = await redis.get(key)
    if not raw:
        return None
    await redis.delete(key)
    try:
        payload = json.loads(raw)
        return payload.get("session_token", ""), payload.get("default_api_key")
    except (ValueError, TypeError):
        return None
