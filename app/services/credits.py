"""
Credit balance bookkeeping.

Every /v1/check that returns a verdict consumes one credit from the
owner's User.credit_balance_checks. Bundle purchases top the balance
up via the Stripe webhook (see services/stripe_billing.py).

The decrement is done via a single UPDATE … WHERE credit_balance_checks > 0
RETURNING credit_balance_checks so two concurrent requests can't both
succeed on the last credit.
"""

import logging

from sqlalchemy import text

from app.services import db

logger = logging.getLogger(__name__)


async def try_charge(user_id: int) -> tuple[bool, int]:
    """
    Atomically deduct one check from the user's balance.

    Returns (charged, new_balance):
      - (True,  new_balance)       deducted successfully
      - (False, 0)                 no balance remaining; caller should 402
    """
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
