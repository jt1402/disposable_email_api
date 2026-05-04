"""
Credit balance bookkeeping + metered usage reporting.

Every /v1/check that returns a verdict is "charged" against the owner's
account. Two modes share the same entry point:

  • billing_mode='bundles' — atomically decrement
    User.credit_balance_checks via UPDATE … RETURNING. Returns
    (False, 0) when out of credit so the caller can 402.

  • billing_mode='metered' — emit one ingestion event to Polar
    (the API_checks meter aggregates them into the monthly invoice).
    Always returns (True, 0) — there is no balance to deplete.

Bundle top-ups arrive via the Polar `order.paid` webhook
(see services/polar_billing.py).
"""

import logging

from sqlalchemy import text

from app.core.config import get_settings
from app.services import db, polar_billing

logger = logging.getLogger(__name__)


async def try_charge(user_id: int) -> tuple[bool, int]:
    """
    Charge one check against the user.

    Returns (charged, new_balance):
      - bundles mode: (True, balance) on success; (False, 0) when empty.
      - metered mode: (True, 0) — Polar invoices the usage.
    """
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        mode = (user.billing_mode if user else "bundles") or "bundles"

    if mode == "metered":
        # Fire-and-forget so a Polar outage doesn't fail otherwise-paid
        # check requests; the user is on a metered plan and we will retry
        # on next request anyway. Worst case we under-bill.
        try:
            settings = get_settings()
            await polar_billing.ingest_event(
                name=settings.polar_meter_event_name,
                external_customer_id=user_id,
            )
        except Exception as exc:
            logger.error("Polar event ingest failed for user %s: %s", user_id, exc)
        return True, 0

    async with db.get_session() as s:
        row = (await s.execute(
            text(
                "UPDATE users "
                "SET credit_balance_checks = credit_balance_checks - 1 "
                "WHERE id = :uid AND credit_balance_checks > 0 "
                "RETURNING credit_balance_checks"
            ),
            {"uid": user_id},
        )).first()
        await s.commit()

    if row is None:
        return False, 0
    return True, int(row[0])


async def get_balance(user_id: int) -> int:
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        return int(user.credit_balance_checks) if user else 0
