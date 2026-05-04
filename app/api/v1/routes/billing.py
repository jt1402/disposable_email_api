"""
Billing routes — Polar checkout for credit bundles + metered subscription.

POST /v1/billing/checkout    Polar Checkout for a one-time credit bundle
POST /v1/billing/subscribe   Polar Checkout for the metered subscription
GET  /v1/billing/balance     credit balance + billing mode for the current user

Bundles model: every successful /v1/check decrements User.credit_balance_checks.
Metered model: every successful /v1/check emits a usage event to Polar; the
billing_mode column gates which path runs. Switching to metered happens via the
`subscription.active` webhook after the user completes Polar checkout.
"""

import logging
import math

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser
from app.core.config import get_settings
from app.models.errors import ErrorDetail
from app.services import db, polar_billing

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])

# Metered unit price in cents. Mirrors the Polar product's per-unit price
# ($0.003 / check). If we ever change pricing, update both this constant
# and the price configured on the Polar metered product.
_METERED_PRICE_CENTS = 0.3


class CheckoutBody(BaseModel):
    bundle: str = Field(description="5k | 10k | 25k | 50k | 100k")


class CheckoutResponse(BaseModel):
    url: str


class BalanceResponse(BaseModel):
    credit_balance_checks: int
    has_purchased: bool
    billing_mode: str = Field(description="bundles | metered")


class UsageResponse(BaseModel):
    available: bool = Field(description="false when user isn't metered or Polar lookup failed")
    events: int = 0
    amount_cents: int = 0
    period_start: str | None = None
    period_end: str | None = None


def _billing_unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=ErrorDetail(
            code="billing_unavailable",
            http_status=503,
            message="Billing is not configured in this environment.",
        ).model_dump(),
    )


def _provider_error() -> HTTPException:
    return HTTPException(
        status_code=502,
        detail=ErrorDetail(
            code="billing_provider_error",
            http_status=502,
            message="Could not start checkout. Please retry.",
        ).model_dump(),
    )


@router.get("/balance", response_model=BalanceResponse)
async def get_balance(current: CurrentUser) -> BalanceResponse:
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        balance = int(user.credit_balance_checks) if user else 0
        has_purchased = bool(user and user.polar_customer_id)
        mode = (user.billing_mode if user else "bundles") or "bundles"
    return BalanceResponse(
        credit_balance_checks=balance,
        has_purchased=has_purchased,
        billing_mode=mode,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(body: CheckoutBody, current: CurrentUser) -> CheckoutResponse:
    settings = get_settings()
    if not settings.polar_access_token:
        raise _billing_unavailable()
    product_id = settings.bundle_product_id(body.bundle)
    credits = settings.bundle_credits(body.bundle)
    if not product_id or credits <= 0:
        raise HTTPException(
            status_code=422,
            detail=ErrorDetail(
                code="invalid_bundle",
                http_status=422,
                message=f"Unknown bundle '{body.bundle}'. Use 5k, 10k, 25k, 50k, or 100k.",
            ).model_dump(),
        )

    success_url = f"{settings.app_base_url.rstrip('/')}/dashboard/billing?checkout=success"
    try:
        url = await polar_billing.create_checkout(
            product_id=product_id,
            customer_email=current.email,
            external_customer_id=str(current.id),
            success_url=success_url,
            metadata={
                "user_id": str(current.id),
                "bundle": body.bundle,
                "kind": "bundle",
            },
        )
    except Exception as exc:
        logger.error("Polar checkout failed for user %s: %s", current.id, exc)
        raise _provider_error() from exc

    return CheckoutResponse(url=url)


@router.get("/usage", response_model=UsageResponse)
async def get_usage(current: CurrentUser) -> UsageResponse:
    """
    Current-period metered usage for the dashboard.

    Period boundaries come from the subscription, but actual consumption
    comes from /v1/customer-meters — the subscription's embedded meters
    array lags behind realtime events by hours, while customer-meters
    matches Polar's own dashboard within seconds.

    Returns available=false for non-metered users (UI then hides the
    panel). Failures degrade to available=false rather than 5xx so a
    Polar outage doesn't break the billing page for everyone.
    """
    settings = get_settings()
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        sub_id = user.polar_subscription_id if user else None
        cust_id = user.polar_customer_id if user else None
        mode = (user.billing_mode if user else "bundles") or "bundles"

    if mode != "metered" or not settings.polar_access_token:
        return UsageResponse(available=False)

    period_start: str | None = None
    period_end: str | None = None
    if sub_id:
        try:
            sub = await polar_billing.get_subscription(sub_id)
            period_start = sub.get("current_period_start")
            period_end = sub.get("current_period_end")
        except Exception as exc:
            logger.error("Polar subscription fetch failed for user %s: %s", current.id, exc)

    events = 0
    if cust_id:
        try:
            meters = await polar_billing.list_customer_meters(cust_id)
            # Our org has a single meter (API_checks); summing is safe.
            # If we ever add a second meter, filter by meter.event_name
            # here to avoid mixing them.
            for m in meters:
                events += int(m.get("consumed_units") or 0)
        except Exception as exc:
            logger.error("Polar customer-meters fetch failed for user %s: %s", current.id, exc)

    # Polar rounds up to whole cents for display ($0.009 → $0.01).
    amount_cents = math.ceil(events * _METERED_PRICE_CENTS) if events else 0

    return UsageResponse(
        available=True,
        events=events,
        amount_cents=amount_cents,
        period_start=period_start,
        period_end=period_end,
    )


@router.post("/cancel-subscription")
async def cancel_subscription(current: CurrentUser) -> dict:
    """
    Schedule the current user's metered subscription to cancel at the
    end of the current billing period.

    Polar issues a final invoice covering the period's metered usage,
    auto-cancels the subscription at period_end, and fires
    `subscription.canceled` to our webhook — where we flip billing_mode
    back to 'bundles'. Until then the user remains on metered.
    """
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        sub_id = user.polar_subscription_id if user else None

    if not sub_id:
        raise HTTPException(
            status_code=409,
            detail=ErrorDetail(
                code="no_active_subscription",
                http_status=409,
                message="No active metered subscription to cancel.",
            ).model_dump(),
        )

    try:
        await polar_billing.cancel_subscription(sub_id)
    except Exception as exc:
        logger.error("Polar cancel failed for user %s: %s", current.id, exc)
        raise _provider_error() from exc

    return {"ok": True}


@router.post("/subscribe", response_model=CheckoutResponse)
async def create_subscription(current: CurrentUser) -> CheckoutResponse:
    """Start a Polar Checkout for the metered subscription product."""
    settings = get_settings()
    if not settings.polar_access_token:
        raise _billing_unavailable()
    product_id = settings.polar_product_metered
    if not product_id:
        raise HTTPException(
            status_code=503,
            detail=ErrorDetail(
                code="metered_unavailable",
                http_status=503,
                message="Metered billing is not configured in this environment.",
            ).model_dump(),
        )

    success_url = f"{settings.app_base_url.rstrip('/')}/dashboard/billing?checkout=success&plan=metered"
    try:
        url = await polar_billing.create_checkout(
            product_id=product_id,
            customer_email=current.email,
            external_customer_id=str(current.id),
            success_url=success_url,
            metadata={
                "user_id": str(current.id),
                "kind": "metered",
            },
        )
    except Exception as exc:
        logger.error("Polar subscribe failed for user %s: %s", current.id, exc)
        raise _provider_error() from exc

    return CheckoutResponse(url=url)
