"""
API key lifecycle — local mirror over Unkey.

The authoritative store for the key *secret* is Unkey. Our Postgres `api_keys`
table is a mirror of metadata so the dashboard can list, name, and revoke keys
without a round-trip for every read.

All functions take `user_id` and return DTOs. The raw key secret is only
returned on `create_for_user` — afterwards the caller can only see the prefix.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from app.services import db, unkey

logger = logging.getLogger(__name__)


@dataclass
class ApiKeyDTO:
    id: int
    name: str
    tier: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


@dataclass
class CreatedApiKey:
    id: int
    key: str  # raw secret — show ONCE, never again
    prefix: str
    name: str
    tier: str


def _to_dto(k: db.ApiKey) -> ApiKeyDTO:
    return ApiKeyDTO(
        id=k.id,
        name=k.name or f"{k.tier} key",
        tier=k.tier,
        prefix=k.unkey_key_prefix or "",
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        revoked_at=k.revoked_at,
    )


async def list_for_user(user_id: int) -> list[ApiKeyDTO]:
    async with db.get_session() as s:
        result = await s.execute(
            select(db.ApiKey)
            .where(db.ApiKey.user_id == user_id)
            .order_by(db.ApiKey.created_at.desc())
        )
        return [_to_dto(k) for k in result.scalars()]


async def create_for_user(
    user_id: int, name: str, tier: str = "free"
) -> CreatedApiKey | None:
    """
    Provision a new Unkey key and mirror it locally. Returns None if Unkey
    refuses (and logs the error). The raw key secret is on the returned DTO
    exactly once — subsequent reads via list_for_user() only expose the prefix.
    """
    # Credit-based billing: Unkey no longer enforces a monthly limit —
    # exhausting the owner's User.credit_balance_checks is what returns 402.
    # Pass -1 so unkey.create_key skips the remaining/refill config entirely.
    result = await unkey.create_key(
        owner_id=str(user_id),
        tier=tier,
        monthly_limit=-1,
        name=name or f"{tier} key",
    )
    if result.error or not result.key_id:
        logger.error("Unkey create_key failed for user %s: %s", user_id, result.error)
        return None

    prefix = (result.key or "")[:8]
    async with db.get_session() as s:
        row = db.ApiKey(
            user_id=user_id,
            unkey_key_id=result.key_id,
            unkey_key_prefix=prefix,
            name=name or f"{tier.capitalize()} key",
            tier=tier,
        )
        s.add(row)
        await s.commit()
        await s.refresh(row)
        return CreatedApiKey(
            id=row.id,
            key=result.key,
            prefix=prefix,
            name=row.name,
            tier=row.tier,
        )


async def revoke_for_user(user_id: int, key_id: int) -> bool:
    """Revoke locally and in Unkey. No-op if already revoked or not owned."""
    async with db.get_session() as s:
        row = await s.get(db.ApiKey, key_id)
        if row is None or row.user_id != user_id or row.revoked_at is not None:
            return False
        await unkey.revoke_key(row.unkey_key_id)
        row.revoked_at = datetime.now(UTC)
        await s.commit()
        return True
