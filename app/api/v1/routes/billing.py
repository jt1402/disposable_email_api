"""
Billing routes — Polar checkout for credit bundles.

POST /v1/billing/checkout    Polar Checkout for a one-time credit bundle
GET  /v1/billing/balance     credit balance for the current user

Every successful /v1/check decrements User.credit_balance_checks. When it
hits zero the API returns 402 quota_exceeded until the user buys another
bundle. Bundle top-ups arrive via the Polar `order.paid` webhook.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser
from app.core.config import get_settings
from app.models.errors import ErrorDetail
from app.services import db, polar_billing

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


class CheckoutBody(BaseModel):
    bundle: str = Field(description="5k | 10k | 25k | 50k | 100k")


class CheckoutResponse(BaseModel):
    url: str


class BalanceResponse(BaseModel):
    credit_balance_checks: int
    has_purchased: bool


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
    return BalanceResponse(
        credit_balance_checks=balance,
        has_purchased=has_purchased,
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
