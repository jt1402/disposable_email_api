"""
Polar billing integration — credit bundles only.

Polar (polar.sh) is our merchant of record for one-time bundle purchases
(5k / 10k / 25k / 50k / 100k checks). The `order.paid` webhook tops up
User.credit_balance_checks; `order.refunded` claws it back.

This module exposes:
  • create_checkout()       create a hosted checkout URL for a bundle
  • verify_webhook()        Standard Webhooks (svix-style) signature check
  • handle_order_paid()     credit a bundle purchase, mark customer
  • handle_order_refunded() reverse a credited bundle on refund

Idempotency: every webhook delivery has a unique `webhook-id` header.
We Redis-SETNX it for 30 days so retried deliveries never double-credit.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Mapping

import httpx
from sqlalchemy import select
from standardwebhooks.webhooks import Webhook
from standardwebhooks.webhooks import WebhookVerificationError as _SWVerifyError

from app.core.config import get_settings
from app.services import db
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

_IDEMPOTENCY_KEY_PREFIX = "polar:webhook:"
_IDEMPOTENCY_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


# ── Webhook signature verification (Standard Webhooks) ───────────────────────


class WebhookVerificationError(Exception):
    pass


def verify_webhook(body: bytes, headers: Mapping[str, str], secret: str) -> dict:
    """
    Verify a Polar webhook using the Standard Webhooks scheme.

    Polar's signing code (server/polar/webhook/tasks.py) does:

        b64secret = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
        wh = StandardWebhook(b64secret)

    i.e. the HMAC key is the raw UTF-8 bytes of the literal secret string
    (including the `polar_whs_` prefix). To verify we mirror exactly: take
    the configured secret string as-is, UTF-8 encode it, base64-encode that,
    and hand the result to the library.
    """
    b64_secret = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
    flat_headers = {k.lower(): v for k, v in headers.items()}

    try:
        wh = Webhook(b64_secret)
        wh.verify(body, flat_headers)
    except _SWVerifyError as exc:
        raise WebhookVerificationError(str(exc)) from exc

    return json.loads(body)


# ── Idempotency ──────────────────────────────────────────────────────────────


async def _already_processed(webhook_id: str) -> bool:
    if not webhook_id:
        return False
    redis = get_redis()
    key = f"{_IDEMPOTENCY_KEY_PREFIX}{webhook_id}"
    was_new = await redis.set_nx_ex(key, "1", _IDEMPOTENCY_TTL_SECONDS)
    return not was_new


# ── Polar REST API client ────────────────────────────────────────────────────


def _client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        base_url=settings.polar_api_base,
        headers={
            "Authorization": f"Bearer {settings.polar_access_token}",
            "Content-Type": "application/json",
        },
        timeout=httpx.Timeout(15.0),
    )


async def create_checkout(
    *,
    product_id: str,
    customer_email: str,
    external_customer_id: str,
    success_url: str,
    metadata: dict[str, str],
) -> str:
    """
    Create a hosted checkout session for a bundle and return the redirect URL.
    `external_customer_id` is stamped on the Polar customer for future
    cross-system reconciliation.
    """
    payload: dict[str, Any] = {
        "products": [product_id],
        "customer_email": customer_email,
        "external_customer_id": external_customer_id,
        "success_url": success_url,
        "metadata": metadata,
    }
    async with _client() as c:
        resp = await c.post("/v1/checkouts/", json=payload)
        if resp.status_code >= 400:
            logger.error(
                "Polar checkout create failed: %s %s", resp.status_code, resp.text
            )
            resp.raise_for_status()
        data = resp.json()
    url = data.get("url") or ""
    if not url:
        raise RuntimeError("Polar response missing 'url' field")
    return url


# ── Webhook handlers ─────────────────────────────────────────────────────────


def _user_id_from_metadata(meta: Mapping[str, Any] | None) -> int | None:
    if not meta:
        return None
    raw = meta.get("user_id")
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    if isinstance(raw, int):
        return raw
    return None


async def handle_order_paid(event: dict, webhook_id: str = "") -> None:
    """
    `order.paid` — a one-time bundle purchase succeeded. Credit the user.
    """
    if await _already_processed(webhook_id):
        logger.info("Polar webhook %s already processed, skipping", webhook_id)
        return

    settings = get_settings()
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}
    customer = data.get("customer") or {}
    customer_email = (customer.get("email") or "").strip().lower()
    polar_customer_id = customer.get("id") or ""

    # Resolve which bundle was purchased. Order items reference product_id;
    # we map that back to "5k"/"10k"/etc. via configured env vars. Prefer
    # explicit metadata.bundle (set at checkout-creation) for resilience.
    bundle = (metadata.get("bundle") or "").strip()
    items = data.get("items") or []
    product_id = ""
    if items:
        product_id = (items[0].get("product_id") or "")
    if not bundle and product_id:
        bundle = settings.bundle_from_product_id(product_id)

    credits = settings.bundle_credits(bundle)
    if credits <= 0:
        logger.error(
            "order.paid with unknown bundle (product=%s, metadata.bundle=%s)",
            product_id, bundle,
        )
        return

    user_id = _user_id_from_metadata(metadata)
    async with db.get_session() as s:
        user = None
        if user_id is not None:
            user = await s.get(db.User, user_id)
        if user is None and customer_email:
            user = (await s.execute(
                select(db.User).where(db.User.email == customer_email)
            )).scalar_one_or_none()
        if user is None:
            logger.error(
                "order.paid without resolvable user (email=%s, meta=%s)",
                customer_email, metadata,
            )
            return

        if polar_customer_id and not user.polar_customer_id:
            user.polar_customer_id = polar_customer_id
        user.credit_balance_checks = (user.credit_balance_checks or 0) + credits
        await s.commit()

    logger.info(
        "Credited %d checks (bundle=%s) to user %s (email=%s)",
        credits, bundle, user.id, customer_email,
    )


async def handle_order_refunded(event: dict, webhook_id: str = "") -> None:
    """
    `order.refunded` — claw back the credits we previously granted, but
    never below zero (the user may have already spent some).
    """
    if await _already_processed(webhook_id):
        return

    settings = get_settings()
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}
    items = data.get("items") or []
    product_id = items[0].get("product_id") if items else ""
    bundle = (metadata.get("bundle") or "").strip() or settings.bundle_from_product_id(product_id or "")
    credits = settings.bundle_credits(bundle)
    if credits <= 0:
        return

    customer = data.get("customer") or {}
    polar_customer_id = customer.get("id") or ""
    user_id = _user_id_from_metadata(metadata)

    async with db.get_session() as s:
        user = None
        if user_id is not None:
            user = await s.get(db.User, user_id)
        if user is None and polar_customer_id:
            user = (await s.execute(
                select(db.User).where(db.User.polar_customer_id == polar_customer_id)
            )).scalar_one_or_none()
        if user is None:
            return
        user.credit_balance_checks = max(0, (user.credit_balance_checks or 0) - credits)
        await s.commit()
    logger.info("Refunded %d checks (bundle=%s) from user %s", credits, bundle, user.id)
