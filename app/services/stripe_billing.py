"""
Stripe billing integration.

Handles subscription webhooks to provision/revoke Unkey API keys automatically.
Flow: checkout.session.completed → upsert User by email → provision Unkey key
      customer.subscription.deleted → revoke Unkey keys for that user
"""

import logging
from datetime import UTC, datetime

import stripe
from sqlalchemy import select

from app.core.config import get_settings
from app.services import db, unkey

logger = logging.getLogger(__name__)


def _price_to_tier(price_id: str) -> str:
    settings = get_settings()
    return {
        settings.stripe_price_starter: "starter",
        settings.stripe_price_growth: "growth",
        settings.stripe_price_pro: "pro",
    }.get(price_id, "free")


async def handle_checkout_completed(session: dict) -> None:
    """
    New or reactivated paid subscription. Idempotent: if the user already has
    an active key on this tier we skip reprovisioning.
    """
    settings = get_settings()
    customer_email = ((session.get("customer_details") or {}).get("email") or "").strip().lower()
    stripe_customer_id = session.get("customer", "")
    price_id = ""

    try:
        stripe.api_key = settings.stripe_secret_key
        line_items = stripe.checkout.Session.list_line_items(session["id"])
        if line_items.data:
            price_id = line_items.data[0].price.id
    except Exception as exc:
        logger.error("Failed to fetch line items: %s", exc)

    tier = _price_to_tier(price_id)
    monthly_limit = settings.tier_limit(tier)

    if not customer_email:
        logger.error("checkout.session.completed without customer email; cannot link to user")
        return

    async with db.get_session() as s:
        # Upsert user by email. Paid checkout without a prior signup is allowed:
        # the email from Stripe becomes the user's email; first magic-link login
        # afterward will mark it verified.
        result = await s.execute(select(db.User).where(db.User.email == customer_email))
        user = result.scalar_one_or_none()
        if user is None:
            user = db.User(email=customer_email, stripe_customer_id=stripe_customer_id)
            s.add(user)
            await s.flush()
        elif not user.stripe_customer_id:
            user.stripe_customer_id = stripe_customer_id

        key_result = await unkey.create_key(
            owner_id=str(user.id),
            tier=tier,
            monthly_limit=monthly_limit,
            name=f"{tier} — {customer_email}",
        )
        if key_result.error:
            logger.error("Failed to create Unkey key for user %s: %s", user.id, key_result.error)
            await s.commit()
            return

        s.add(
            db.ApiKey(
                user_id=user.id,
                unkey_key_id=key_result.key_id,
                unkey_key_prefix=(key_result.key or "")[:8],
                name=f"{tier.capitalize()} plan",
                tier=tier,
            )
        )
        await s.commit()

    logger.info("Provisioned %s key for user %s", tier, customer_email)


async def handle_subscription_deleted(subscription: dict) -> None:
    """Revoke all active keys for the subscription's customer."""
    stripe_customer_id = subscription.get("customer", "")
    if not stripe_customer_id:
        return

    async with db.get_session() as s:
        result = await s.execute(
            select(db.User).where(db.User.stripe_customer_id == stripe_customer_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            return

        keys_result = await s.execute(
            select(db.ApiKey).where(
                db.ApiKey.user_id == user.id,
                db.ApiKey.revoked_at.is_(None),
            )
        )
        for key in keys_result.scalars():
            await unkey.revoke_key(key.unkey_key_id)
            key.revoked_at = datetime.now(UTC)

        await s.commit()

    logger.info("Revoked keys for stripe_customer %s", stripe_customer_id)
