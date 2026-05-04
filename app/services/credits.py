"""
Credit balance bookkeeping + metered usage reporting.

Every /v1/check that returns a verdict is "charged" against the owner's
account via try_charge():

  • billing_mode='bundles'  — decrement User.credit_balance_checks
    atomically (UPDATE … RETURNING). Returns (False, 0) when empty so
    the caller can return 402.

  • billing_mode='metered'  — burn down any remaining credit balance
    first, then once it hits 0 emit a usage event to Polar. Users who
    bought bundles before subscribing get full value of those credits;
    once exhausted the meter takes over and Polar invoices monthly.

Bundle top-ups arrive via the Polar `order.paid` webhook
(see services/polar_billing.py).
"""

import logging

from sqlalchemy import text

from app.core.config import get_settings
from app.services import db, polar_billing

logger = logging.getLogger(__name__)


_DECREMENT_SQL = text(
    "UPDATE users "
    "SET credit_balance_checks = credit_balance_checks - 1 "
    "WHERE id = :uid AND credit_balance_checks > 0 "
    "RETURNING credit_balance_checks"
)


async def _try_decrement(user_id: int) -> int | None:
    async with db.get_session() as s:
        row = (await s.execute(_DECREMENT_SQL, {"uid": user_id})).first()
        await s.commit()
    return int(row[0]) if row else None


async def try_charge(user_id: int) -> tuple[bool, int]:
    """
    Charge one check against the user.

    Returns (charged, new_balance):
      - bundles mode: (True, balance) on success; (False, 0) when empty.
      - metered mode: (True, balance) while credits remain (burn-down);
        (True, 0) once depleted (Polar invoices the usage).
    """
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        mode = (user.billing_mode if user else "bundles") or "bundles"

    if mode == "metered":
        # Burn-down: spend any remaining bundle credits first so the user
        # gets full value of pre-paid bundles even while subscribed. Only
        # once the balance is empty do we start metering Polar.
        new_balance = await _try_decrement(user_id)
        if new_balance is not None:
            return True, new_balance

        # Out of pre-paid credits — emit the metered event. Fire-and-forget
        # so a Polar outage doesn't fail otherwise-valid requests; worst
        # case we under-bill (the user already paid for the subscription).
        try:
            settings = get_settings()
            await polar_billing.ingest_event(
                name=settings.polar_meter_event_name,
                external_customer_id=user_id,
            )
        except Exception as exc:
            logger.error("Polar event ingest failed for user %s: %s", user_id, exc)
        return True, 0

    new_balance = await _try_decrement(user_id)
    if new_balance is None:
        return False, 0
    return True, new_balance


async def get_balance(user_id: int) -> int:
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        return int(user.credit_balance_checks) if user else 0
