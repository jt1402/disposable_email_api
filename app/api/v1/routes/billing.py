"""
Billing routes — Stripe checkout for credit bundles + account balance.

POST /v1/billing/checkout   create a Stripe Checkout Session for a bundle
GET  /v1/billing/balance    current credit balance for the logged-in user

Model: one-time bundle purchases (mode: "payment"). Every successful
/v1/check decrements User.credit_balance_checks by 1. When the balance
runs out, /v1/check returns 402 and the user buys a bundle.
"""

import logging

import stripe
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser
from app.core.config import get_settings
from app.models.errors import ErrorDetail
from app.services import db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


class CheckoutBody(BaseModel):
    bundle: str = Field(description="10k | 50k | 250k")


class CheckoutResponse(BaseModel):
    url: str


class BalanceResponse(BaseModel):
    credit_balance_checks: int
    has_purchased: bool


@router.get("/balance", response_model=BalanceResponse)
async def get_balance(current: CurrentUser) -> BalanceResponse:
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        balance = int(user.credit_balance_checks) if user else 0
        has_purchased = bool(user and user.stripe_customer_id)
    return BalanceResponse(
        credit_balance_checks=balance,
        has_purchased=has_purchased,
    )


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
    price = settings.bundle_price_id(body.bundle)
    credits = settings.bundle_credits(body.bundle)
    if not price or credits <= 0:
        raise HTTPException(
            status_code=422,
            detail=ErrorDetail(
                code="invalid_bundle",
                http_status=422,
                message=f"Unknown bundle '{body.bundle}'. Use 10k, 50k, or 250k.",
            ).model_dump(),
        )

    # Reuse an existing Stripe customer if we have one so all invoices land
    # on the same account; first-time purchasers checkout as customer_email.
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        stripe_customer_id = user.stripe_customer_id if user else None

    stripe.api_key = settings.stripe_secret_key
    try:
        session_kwargs: dict = {
            "mode": "payment",
            "line_items": [{"price": price, "quantity": 1}],
            "success_url": f"{settings.app_base_url.rstrip('/')}/dashboard/billing?checkout=success",
            "cancel_url": f"{settings.app_base_url.rstrip('/')}/dashboard/billing?checkout=cancelled",
            "client_reference_id": str(current.id),
            "metadata": {"user_id": str(current.id), "bundle": body.bundle},
        }
        if stripe_customer_id:
            session_kwargs["customer"] = stripe_customer_id
        else:
            session_kwargs["customer_email"] = current.email
            # mode=payment defaults to customer_creation='if_required' which often
            # skips customer creation entirely, leaving session.customer null and
            # our has_purchased gate stuck at False. Force creation every time.
            session_kwargs["customer_creation"] = "always"
        session = stripe.checkout.Session.create(**session_kwargs)
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
