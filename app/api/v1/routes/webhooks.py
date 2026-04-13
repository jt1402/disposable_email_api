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
        event_type = event["type"]
        event_data = event["data"]["object"]
    except stripe.SignatureVerificationError:
        # Try v2 thin event format (Stripe Workbench)
        try:
            thin_event = stripe.Webhook.construct_thin_event(
                payload, stripe_signature, settings.stripe_webhook_secret
            )
            event_type = thin_event.type
            # Fetch full event data for thin events
            full_event = stripe.Event.retrieve(thin_event.id)
            event_data = full_event["data"]["object"]
        except Exception:
            logger.warning("Invalid Stripe webhook signature")
            raise HTTPException(status_code=400, detail="Invalid signature")

    logger.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        await handle_checkout_completed(event_data)
    elif event_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        await handle_subscription_deleted(event_data)

    return {"received": True}
