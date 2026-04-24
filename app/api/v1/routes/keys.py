"""
Dashboard API key management.

Auth: session Bearer token (via `require_user`).
The secret is only returned once, on POST /v1/keys — after that the client
can only see the prefix (`dc_abcd…`) and metadata.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import CurrentUser
from app.models.errors import ErrorDetail
from app.services import db, keys as keys_svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/keys", tags=["keys"])

# Unpaid accounts are capped at 1 active key. The cap lifts the moment a
# bundle purchase is recorded via the Stripe webhook (sets stripe_customer_id).
_FREE_KEY_LIMIT = 1


class CreateKeyBody(BaseModel):
    name: str = Field(default="", max_length=80)


class KeySummary(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None
    revoked_at: str | None


class CreatedKeyResponse(BaseModel):
    id: int
    name: str
    prefix: str
    key: str = Field(description="Raw secret — shown once. Store it securely.")


def _summary(k: keys_svc.ApiKeyDTO) -> KeySummary:
    return KeySummary(
        id=k.id,
        name=k.name,
        prefix=k.prefix,
        created_at=k.created_at.isoformat(),
        last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        revoked_at=k.revoked_at.isoformat() if k.revoked_at else None,
    )


@router.get("", response_model=list[KeySummary])
async def list_keys(current: CurrentUser) -> list[KeySummary]:
    rows = await keys_svc.list_for_user(current.id)
    return [_summary(k) for k in rows]


@router.post("", response_model=CreatedKeyResponse, status_code=201)
async def create_key(body: CreateKeyBody, current: CurrentUser) -> CreatedKeyResponse:
    async with db.get_session() as s:
        user = await s.get(db.User, current.id)
        has_purchased = bool(user and user.stripe_customer_id)
        if not has_purchased:
            active_count = (
                await s.execute(
                    select(func.count())
                    .select_from(db.ApiKey)
                    .where(db.ApiKey.user_id == current.id)
                    .where(db.ApiKey.revoked_at.is_(None))
                )
            ).scalar_one() or 0
            if active_count >= _FREE_KEY_LIMIT:
                raise HTTPException(
                    status_code=403,
                    detail=ErrorDetail(
                        code="free_key_limit_reached",
                        http_status=403,
                        message=(
                            "Free accounts are limited to one API key. "
                            "Buy a credit bundle to unlock additional keys."
                        ),
                        upgrade_url="/dashboard/billing",
                    ).model_dump(),
                )

    created = await keys_svc.create_for_user(user_id=current.id, name=body.name)
    if created is None:
        raise HTTPException(
            status_code=502,
            detail=ErrorDetail(
                code="key_provisioning_failed",
                http_status=502,
                message="Could not provision the API key. Please retry in a moment.",
            ).model_dump(),
        )
    return CreatedKeyResponse(
        id=created.id,
        name=created.name,
        prefix=created.prefix,
        key=created.key,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_key(key_id: int, current: CurrentUser) -> None:
    ok = await keys_svc.revoke_for_user(current.id, key_id)
    if not ok:
        raise HTTPException(status_code=404, detail={"code": "key_not_found"})
