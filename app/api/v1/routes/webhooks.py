"""
POST /v1/webhooks/polar

Polar sends signed webhook events here using the Standard Webhooks scheme
(https://www.standardwebhooks.com/). Signature is verified before any
side-effects so a spoofed POST cannot grant credits.
"""

import logging

from fastapi import APIRouter, HTTPException, Request

from app.core.config import get_settings
from app.services.polar_billing import (
    WebhookVerificationError,
    handle_order_paid,
    handle_order_refunded,
    handle_subscription_active,
    handle_subscription_inactive,
    verify_webhook,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/v1/webhooks/polar", include_in_schema=False)
async def polar_webhook(request: Request) -> dict:
    settings = get_settings()
    if not settings.polar_webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")

    body = await request.body()
    try:
        event = verify_webhook(body, request.headers, settings.polar_webhook_secret)
    except WebhookVerificationError as exc:
        # Log just enough to debug without leaking secrets. The first few
        # chars of the configured secret prove which secret the env var
        # currently holds (sandbox vs prod vs something else).
        secret_hint = (settings.polar_webhook_secret or "")[:14] + "…"
        sig_hint = (request.headers.get("webhook-signature") or "")[:24] + "…"
        logger.warning(
            "Polar webhook signature failed: %s | secret=%s | sig=%s | id=%s",
            exc, secret_hint, sig_hint, request.headers.get("webhook-id", ""),
        )
        raise HTTPException(status_code=400, detail="Invalid signature") from exc

    event_type = event.get("type", "")
    webhook_id = request.headers.get("webhook-id", "")
    logger.info("Polar webhook: %s (id=%s)", event_type, webhook_id)

    if event_type == "order.paid":
        await handle_order_paid(event, webhook_id=webhook_id)
    elif event_type == "order.refunded":
        await handle_order_refunded(event, webhook_id=webhook_id)
    elif event_type in ("subscription.created", "subscription.active"):
        await handle_subscription_active(event, webhook_id=webhook_id)
    elif event_type in ("subscription.canceled", "subscription.revoked"):
        await handle_subscription_inactive(event, webhook_id=webhook_id)
    else:
        # Subscribed-but-unhandled events (e.g. subscription.updated) are
        # still acknowledged with 200 so Polar doesn't retry forever.
        logger.info("Polar webhook %s ignored", event_type)

    return {"received": True}
