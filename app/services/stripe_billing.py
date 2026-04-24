"""
Stripe billing integration — credit bundles (PAYG + top-ups).

Model: every /v1/check decrements User.credit_balance_checks. When a user
runs low, they buy a bundle (10k / 50k / 250k) via Stripe Checkout. The
`checkout.session.completed` webhook adds the bundle's credits to the user's
balance. No subscriptions — each purchase is a one-time `mode: "payment"`
Checkout Session.

Idempotency is handled via Stripe's event id: we record the event id in a
Redis set with a 30-day TTL so a replayed webhook never double-credits.
"""

import logging

import stripe
from sqlalchemy import select

from app.core.config import get_settings
from app.services import db
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

_IDEMPOTENCY_KEY_PREFIX = "stripe:event:"
_IDEMPOTENCY_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


async def _already_processed(event_id: str) -> bool:
    """Use Redis SETNX for webhook idempotency. Returns True if already seen."""
    if not event_id:
        return False
    redis = get_redis()
    key = f"{_IDEMPOTENCY_KEY_PREFIX}{event_id}"
    was_new = await redis.set_nx_ex(key, "1", _IDEMPOTENCY_TTL_SECONDS)
    return not was_new


def _bundle_from_price(price_id: str) -> str:
    settings = get_settings()
    return {
        settings.stripe_price_bundle_10k: "10k",
        settings.stripe_price_bundle_50k: "50k",
        settings.stripe_price_bundle_250k: "250k",
    }.get(price_id, "")


async def handle_checkout_completed(session: dict, event_id: str = "") -> None:
    """
    Bundle purchase completed. Add the bundle's credits to the user's balance.
    Idempotent via Stripe event id so replayed webhooks don't double-credit.
    """
    if await _already_processed(event_id):
        logger.info("Stripe event %s already processed, skipping", event_id)
        return

    settings = get_settings()
    customer_email = ((session.get("customer_details") or {}).get("email") or "").strip().lower()
    stripe_customer_id = session.get("customer", "")
    client_reference_id = session.get("client_reference_id") or ""
    metadata = session.get("metadata") or {}
    bundle = metadata.get("bundle", "")
    price_id = ""

    try:
        stripe.api_key = settings.stripe_secret_key
        line_items = stripe.checkout.Session.list_line_items(session["id"])
        if line_items.data:
            price_id = line_items.data[0].price.id
    except Exception as exc:
        logger.error("Failed to fetch line items: %s", exc)

    # Prefer the explicit metadata.bundle we set at checkout-creation time;
    # fall back to mapping the price id so legacy sessions still resolve.
    if not bundle:
        bundle = _bundle_from_price(price_id)

    credits = settings.bundle_credits(bundle)
    if credits <= 0:
        logger.error(
            "checkout.session.completed with unknown bundle (price=%s, metadata.bundle=%s)",
            price_id, bundle,
        )
        return

    async with db.get_session() as s:
        user = None
        # Prefer client_reference_id (the user.id we set at checkout-creation).
        if client_reference_id and client_reference_id.isdigit():
            user = await s.get(db.User, int(client_reference_id))
        if user is None and customer_email:
            result = await s.execute(select(db.User).where(db.User.email == customer_email))
            user = result.scalar_one_or_none()
        if user is None:
            logger.error(
                "checkout.session.completed without resolvable user (email=%s, ref=%s)",
                customer_email, client_reference_id,
            )
            return

        if stripe_customer_id and not user.stripe_customer_id:
            user.stripe_customer_id = stripe_customer_id
        user.credit_balance_checks = (user.credit_balance_checks or 0) + credits
        await s.commit()

    logger.info(
        "Credited %d checks (bundle=%s) to user %s (email=%s)",
        credits, bundle, user.id, customer_email,
    )
