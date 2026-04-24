"""
Billing routes — Stripe checkout initiation.

The dashboard's "Upgrade" button calls POST /v1/billing/checkout with the tier
name; we create a Stripe Checkout Session and return its URL. The resulting
webhook (see routes/webhooks.py) upserts the User's stripe_customer_id and
provisions the paid-tier Unkey key.
"""

import logging

import stripe
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser
from app.core.config import get_settings
from app.models.errors import ErrorDetail

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


class CheckoutBody(BaseModel):
    tier: str = Field(description="starter | growth | pro")


class CheckoutResponse(BaseModel):
    url: str


def _price_for(tier: str) -> str:
    settings = get_settings()
    return {
        "starter": settings.stripe_price_starter,
        "growth": settings.stripe_price_growth,
        "pro": settings.stripe_price_pro,
    }.get(tier, "")


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(body: CheckoutBody, current: CurrentUser) -> CheckoutResponse:
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail=ErrorDetail(
                code="billing_unavailable",
                http_status=503,
                message="Billing is not configured in this environment.",
            ).model_dump(),
        )
    price = _price_for(body.tier)
    if not price:
        raise HTTPException(
            status_code=422,
            detail=ErrorDetail(
                code="invalid_tier",
                http_status=422,
                message=f"Unknown tier '{body.tier}'. Use starter, growth, or pro.",
            ).model_dump(),
        )

    stripe.api_key = settings.stripe_secret_key
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price, "quantity": 1}],
            customer_email=current.email,
            success_url=f"{settings.app_base_url.rstrip('/')}/dashboard?checkout=success",
            cancel_url=f"{settings.app_base_url.rstrip('/')}/pricing?checkout=cancelled",
            client_reference_id=str(current.id),
            metadata={"user_id": str(current.id), "tier": body.tier},
        )
    except stripe.StripeError as exc:
        logger.error("Stripe checkout.create failed for user %s: %s", current.id, exc)
        raise HTTPException(
            status_code=502,
            detail=ErrorDetail(
                code="billing_provider_error",
                http_status=502,
                message="Could not start checkout. Please retry.",
            ).model_dump(),
        ) from exc

    return CheckoutResponse(url=session.url or "")
