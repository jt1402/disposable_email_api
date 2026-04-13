"""
Unkey integration — API key verification and provisioning.

Using the REST API directly (not an SDK) for stability and transparency.
Docs: https://unkey.dev/docs/api-reference
"""

import logging
from dataclasses import dataclass

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

UNKEY_BASE = "https://api.unkey.com"


@dataclass
class VerifyResult:
    valid: bool
    key_id: str = ""
    owner_id: str = ""
    tier: str = "free"
    remaining: int | None = None
    error: str = ""


@dataclass
class CreateKeyResult:
    key: str = ""
    key_id: str = ""
    error: str = ""


async def verify_key(api_key: str) -> VerifyResult:
    settings = get_settings()
    if not settings.unkey_api_id:
        # Dev mode: no Unkey configured, allow all keys
        logger.warning("UNKEY_API_ID not set — running in dev mode, all keys accepted")
        return VerifyResult(valid=True, key_id="dev", owner_id="dev", tier="pro")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{UNKEY_BASE}/v2/keys.verifyKey",
                json={"key": api_key},
                headers={"Authorization": f"Bearer {settings.unkey_root_key}"},
            )
        if resp.status_code != 200:
            logger.error("Unkey returned %s: %s", resp.status_code, resp.text)
            return VerifyResult(valid=False, error="auth_service_unavailable")
        data = resp.json().get("data", {})
    except httpx.RequestError as exc:
        logger.error("Unkey request failed: %s", exc)
        return VerifyResult(valid=False, error="auth_service_unavailable")

    if not data.get("valid"):
        return VerifyResult(valid=False, error=data.get("code", "invalid_key"))

    # meta.tier is stored when the key is created (set per Stripe plan)
    tier = (data.get("meta") or {}).get("tier", "free")

    return VerifyResult(
        valid=True,
        key_id=data.get("keyId", ""),
        owner_id=data.get("externalId", data.get("ownerId", "")),
        tier=tier,
        remaining=(data.get("credits") or {}).get("remaining", data.get("remaining")),
    )


async def create_key(
    owner_id: str,
    tier: str,
    monthly_limit: int,
    name: str = "",
) -> CreateKeyResult:
    settings = get_settings()
    if not settings.unkey_root_key:
        return CreateKeyResult(error="UNKEY_ROOT_KEY not configured")

    payload: dict = {
        "apiId": settings.unkey_api_id,
        "externalId": owner_id,
        "meta": {"tier": tier},
        "name": name or f"{tier} key for {owner_id}",
        "prefix": "dc",  # "dc_" prefix — recognisable brand prefix
    }

    if monthly_limit > 0:
        payload["credits"] = {
            "remaining": monthly_limit,
            "refill": {
                "interval": "monthly",
                "amount": monthly_limit,
                "refillDay": 1,
            },
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{UNKEY_BASE}/v2/keys.createKey",
                headers={"Authorization": f"Bearer {settings.unkey_root_key}"},
                json=payload,
            )
        if resp.status_code != 200:
            logger.error("Unkey createKey returned %s: %s", resp.status_code, resp.text)
            return CreateKeyResult(error=f"unkey_http_{resp.status_code}")
        data = resp.json().get("data", resp.json())
    except httpx.RequestError as exc:
        logger.error("Unkey create key request failed: %s", exc)
        return CreateKeyResult(error="auth_service_unavailable")

    if "error" in data:
        return CreateKeyResult(error=data["error"])

    return CreateKeyResult(key=data.get("key", ""), key_id=data.get("keyId", ""))


async def revoke_key(key_id: str) -> bool:
    settings = get_settings()
    if not settings.unkey_root_key:
        return False

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{UNKEY_BASE}/v2/keys.deleteKey",
                headers={"Authorization": f"Bearer {settings.unkey_root_key}"},
                json={"keyId": key_id},
            )
            return resp.status_code == 200
    except httpx.RequestError:
        return False
