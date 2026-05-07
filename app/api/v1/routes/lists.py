"""
Per-user custom allow / block lists.

Domains on the allowlist are forced to recommendation=allow; domains on the
blocklist are forced to recommendation=block. Both bypass the detection
pipeline entirely (path_taken='custom_list'). Allow takes precedence over
block when a domain ends up on both lists.

All endpoints require a session (dashboard-only). Lists are scoped to the
user — every API key the user owns shares the same overrides.
"""

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field

from app.api.v1.deps import CurrentUser
from app.services import custom_lists
from app.services.redis_client import get_redis

router = APIRouter(prefix="/lists", tags=["lists"])

_KIND_PATTERN = r"^(allow|block|reviewed)$"


class ListResponse(BaseModel):
    kind: str
    domains: list[str]


class AddRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)


class AddResponse(BaseModel):
    kind: str
    domain: str
    added: bool


class RemoveResponse(BaseModel):
    kind: str
    domain: str
    removed: bool


@router.get("/{kind}", response_model=ListResponse)
async def list_custom(
    current: CurrentUser,
    kind: str = Path(..., pattern=_KIND_PATTERN),
) -> ListResponse:
    redis = get_redis()
    domains = await custom_lists.list_domains(redis, current.id, kind)
    return ListResponse(kind=kind, domains=domains)


@router.post("/{kind}", response_model=AddResponse)
async def add_custom(
    body: AddRequest,
    current: CurrentUser,
    kind: str = Path(..., pattern=_KIND_PATTERN),
) -> AddResponse:
    redis = get_redis()
    added = await custom_lists.add_domain(redis, current.id, kind, body.domain)
    return AddResponse(kind=kind, domain=body.domain.strip().lower(), added=added)


@router.delete("/{kind}/{domain}", response_model=RemoveResponse)
async def remove_custom(
    current: CurrentUser,
    kind: str = Path(..., pattern=_KIND_PATTERN),
    domain: str = Path(..., min_length=3, max_length=255),
) -> RemoveResponse:
    redis = get_redis()
    removed = await custom_lists.remove_domain(redis, current.id, kind, domain)
    if not removed:
        raise HTTPException(status_code=404, detail={"code": "not_in_list", "message": f"{domain} not found in {kind}list"})
    return RemoveResponse(kind=kind, domain=domain.strip().lower(), removed=removed)
