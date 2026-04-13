"""
POST /webhooks/stripe

Stripe sends signed webhook events here.
Signature verified before any processing to prevent spoofing.
"""

import logging

import stripe
from fastapi import APIRouter, Header, HTTPException, Request

from app.core.config import get_settings
from app.services.stripe_billing import handle_checkout_completed, handle_subscription_deleted

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/webhooks/stripe", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(None, alias="Stripe-Signature"),
) -> dict:
    settings = get_settings()
    payload = await request.body()

    if not stripe_signature or not settings.stripe_webhook_secret:
        raise HTTPException(status_code=400, detail="Missing signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret
        )
    except stripe.SignatureVerificationError:
        logger.warning("Invalid Stripe webhook signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    logger.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        await handle_checkout_completed(event["data"]["object"])
    elif event_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        await handle_subscription_deleted(event["data"]["object"])

    return {"received": True}
