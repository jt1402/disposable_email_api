"""
Stripe billing integration.

Handles subscription webhooks to provision/revoke Unkey API keys automatically.
Flow: checkout.session.completed → create Unkey key → store in DB
      customer.subscription.deleted → revoke Unkey key → update DB
"""

import logging
from datetime import datetime, timezone

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
    Called when a new subscription payment succeeds.
    Creates customer record + Unkey API key.
    """
    settings = get_settings()
    customer_email = session.get("customer_details", {}).get("email", "")
    stripe_customer_id = session.get("customer", "")
    price_id = ""

    # Get the price from the line items
    try:
        stripe.api_key = settings.stripe_secret_key
        line_items = stripe.checkout.Session.list_line_items(session["id"])
        if line_items.data:
            price_id = line_items.data[0].price.id
    except Exception as exc:
        logger.error("Failed to fetch line items: %s", exc)

    tier = _price_to_tier(price_id)
    monthly_limit = settings.tier_limit(tier)

    async with db.get_session() as session_db:
        # Upsert customer
        result = await session_db.execute(
            select(db.Customer).where(db.Customer.stripe_customer_id == stripe_customer_id)
        )
        customer = result.scalar_one_or_none()
        if not customer:
            customer = db.Customer(
                stripe_customer_id=stripe_customer_id,
                email=customer_email,
            )
            session_db.add(customer)
            await session_db.flush()

        # Create Unkey key
        key_result = await unkey.create_key(
            owner_id=str(customer.id),
            tier=tier,
            monthly_limit=monthly_limit,
            name=f"{tier} — {customer_email}",
        )

        if key_result.error:
            logger.error("Failed to create Unkey key for customer %s: %s", customer.id, key_result.error)
            return

        api_key_record = db.ApiKey(
            customer_id=customer.id,
            unkey_key_id=key_result.key_id,
            tier=tier,
        )
        session_db.add(api_key_record)
        await session_db.commit()

    logger.info("Provisioned %s key for customer %s", tier, stripe_customer_id)


async def handle_subscription_deleted(subscription: dict) -> None:
    """Revoke the API key when a subscription is cancelled."""
    stripe_customer_id = subscription.get("customer", "")

    async with db.get_session() as session_db:
        result = await session_db.execute(
            select(db.Customer).where(db.Customer.stripe_customer_id == stripe_customer_id)
        )
        customer = result.scalar_one_or_none()
        if not customer:
            return

        keys_result = await session_db.execute(
            select(db.ApiKey).where(
                db.ApiKey.customer_id == customer.id,
                db.ApiKey.revoked_at.is_(None),
            )
        )
        for key in keys_result.scalars():
            await unkey.revoke_key(key.unkey_key_id)
            key.revoked_at = datetime.now(timezone.utc)

        await session_db.commit()

    logger.info("Revoked keys for customer %s", stripe_customer_id)
