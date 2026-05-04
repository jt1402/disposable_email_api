"""
Credit balance bookkeeping.

Every /v1/check that returns a verdict decrements User.credit_balance_checks
atomically via try_charge() — UPDATE … RETURNING returns the new balance,
or None if the row was already at zero. Returning (False, 0) lets the
caller raise 402.

Bundle top-ups arrive via the Polar `order.paid` webhook
(see services/polar_billing.py).
"""

import logging

from sqlalchemy import text

from app.services import db

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

    Returns (charged, new_balance): (True, balance) on success;
    (False, 0) when the credit balance is already empty.
    """
    new_balance = await _try_decrement(user_id)
    if new_balance is None:
        return False, 0
    return True, new_balance


async def get_balance(user_id: int) -> int:
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        return int(user.credit_balance_checks) if user else 0
