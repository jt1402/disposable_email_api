"""
Usage dashboard endpoints.

All queries are scoped to the caller's API keys. We look up the Unkey key_ids
owned by the user, then aggregate `checks` rows whose `api_key_id` column
matches. If the user has no keys, responses are empty (not an error).
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select

from app.api.v1.deps import CurrentUser
from app.services import custom_lists, db
from app.services.redis_client import get_redis

router = APIRouter(prefix="/usage", tags=["usage"])


async def _key_ids_for_user(user_id: int) -> list[str]:
    """
    All api_key_id values that should count toward this user's usage:
    the Unkey key ids of their real keys plus the synthetic 'playground:{id}'
    tag we write for dashboard /playground runs (those drain credits too).
    """
    async with db.get_session() as s:
        result = await s.execute(
            select(db.ApiKey.unkey_key_id).where(db.ApiKey.user_id == user_id)
        )
        ids = [row for row in result.scalars() if row]
    ids.append(f"playground:{user_id}")
    return ids


class UsageSummary(BaseModel):
    total_checks: int
    checks_this_period: int
    period_start: str
    blocks: int
    verify_manually: int
    allow_with_flag: int
    allows: int
    avg_latency_ms: float
    cache_hit_rate: float


@router.get("/summary", response_model=UsageSummary)
async def usage_summary(current: CurrentUser) -> UsageSummary:
    """
    Rolled-up usage stats for the caller. Period = current calendar month
    (matches Unkey's monthly refill day). `checks_this_period` is what the
    dashboard's quota bar reads from.
    """
    key_ids = await _key_ids_for_user(current.id)
    now = datetime.now(UTC)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    async with db.get_session() as s:
        all_time_stmt = select(func.count()).where(db.Check.api_key_id.in_(key_ids))
        total_checks = (await s.execute(all_time_stmt)).scalar_one() or 0

        period_stmt = (
            select(
                func.count().label("n"),
                func.sum(case((db.Check.recommendation == "block", 1), else_=0)).label("blocks"),
                func.sum(
                    case((db.Check.recommendation == "verify_manually", 1), else_=0)
                ).label("vm"),
                func.sum(
                    case((db.Check.recommendation == "allow_with_flag", 1), else_=0)
                ).label("awf"),
                func.sum(case((db.Check.recommendation == "allow", 1), else_=0)).label("allows"),
                func.avg(db.Check.latency_ms).label("avg_latency"),
                func.sum(case((db.Check.cached, 1), else_=0)).label("cached_count"),
            )
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.checked_at >= period_start)
        )
        row = (await s.execute(period_stmt)).one()
        n = int(row.n or 0)
        cached_count = int(row.cached_count or 0)

        return UsageSummary(
            total_checks=int(total_checks),
            checks_this_period=n,
            period_start=period_start.isoformat(),
            blocks=int(row.blocks or 0),
            verify_manually=int(row.vm or 0),
            allow_with_flag=int(row.awf or 0),
            allows=int(row.allows or 0),
            avg_latency_ms=float(row.avg_latency or 0.0),
            cache_hit_rate=(cached_count / n) if n > 0 else 0.0,
        )


class DailyBucket(BaseModel):
    date: str  # YYYY-MM-DD
    total: int
    blocks: int


class ByDayResponse(BaseModel):
    days: int
    buckets: list[DailyBucket]


@router.get("/by_day", response_model=ByDayResponse)
async def usage_by_day(
    current: CurrentUser,
    days: int = Query(default=30, ge=1, le=365),
) -> ByDayResponse:
    """Time-series for the usage chart. One row per calendar day (UTC)."""
    key_ids = await _key_ids_for_user(current.id)
    cutoff = datetime.now(UTC) - timedelta(days=days)
    day_expr = func.date_trunc("day", db.Check.checked_at)
    async with db.get_session() as s:
        stmt = (
            select(
                day_expr.label("day"),
                func.count().label("n"),
                func.sum(case((db.Check.recommendation == "block", 1), else_=0)).label("blocks"),
            )
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.checked_at >= cutoff)
            .group_by(day_expr)
            .order_by(day_expr)
        )
        rows = (await s.execute(stmt)).all()

    return ByDayResponse(
        days=days,
        buckets=[
            DailyBucket(
                date=r.day.date().isoformat(),
                total=int(r.n or 0),
                blocks=int(r.blocks or 0),
            )
            for r in rows
        ],
    )


class RecentCheck(BaseModel):
    domain: str
    risk_score: int
    recommendation: str
    risk_level: str | None = None
    confidence_level: str | None = None
    disposable: bool | None = None
    latency_ms: int
    cached: bool
    checked_at: str


class RecentResponse(BaseModel):
    items: list[RecentCheck]


@router.get("/recent", response_model=RecentResponse)
async def recent_checks(
    current: CurrentUser,
    limit: int = Query(default=50, ge=1, le=500),
) -> RecentResponse:
    """Latest N checks across all of the user's keys. Domain only — no emails."""
    key_ids = await _key_ids_for_user(current.id)
    async with db.get_session() as s:
        stmt = (
            select(db.Check)
            .where(db.Check.api_key_id.in_(key_ids))
            .order_by(db.Check.checked_at.desc())
            .limit(limit)
        )
        rows = (await s.execute(stmt)).scalars().all()

    return RecentResponse(
        items=[
            RecentCheck(
                domain=r.domain,
                risk_score=r.risk_score,
                recommendation=r.recommendation,
                risk_level=r.risk_level,
                confidence_level=r.confidence_level,
                disposable=r.disposable,
                latency_ms=r.latency_ms,
                cached=r.cached,
                checked_at=r.checked_at.isoformat(),
            )
            for r in rows
        ]
    )


# ── Domain Activity (per-user, aggregated) ──────────────────────────────────

class DomainBreakdown(BaseModel):
    blocks: int
    verify_manually: int
    allow_with_flag: int
    allows: int


class DomainRow(BaseModel):
    domain: str
    total: int
    breakdown: DomainBreakdown
    last_seen: str
    last_recommendation: str
    in_allow_list: bool
    in_block_list: bool


class DomainsResponse(BaseModel):
    items: list[DomainRow]
    total: int


_REC_VALUES = ("allow", "allow_with_flag", "verify_manually", "block")


@router.get("/domains", response_model=DomainsResponse)
async def domains(
    current: CurrentUser,
    recommendation: str | None = Query(default=None, description="Filter: only domains where the latest recommendation matches"),
    since_days: int = Query(default=30, ge=1, le=365),
    in_list: str | None = Query(default=None, description="allow | block | none"),
    q: str | None = Query(default=None, max_length=255, description="Substring match on domain"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> DomainsResponse:
    """
    Per-domain rollup of the caller's check history. Powers the Domain
    Activity dashboard page. Scoped to the caller's keys + their playground
    activity. Joins live against Redis to flag domains that are already on
    their custom allow/block lists.
    """
    if recommendation is not None and recommendation not in _REC_VALUES:
        recommendation = None

    key_ids = await _key_ids_for_user(current.id)
    cutoff = datetime.now(UTC) - timedelta(days=since_days)

    async with db.get_session() as s:
        # Subquery: per-domain aggregates over the window. last_recommendation
        # comes from the row with the latest checked_at via a correlated
        # MAX/argmax pattern done with a window function.
        latest_per_domain = (
            select(
                db.Check.domain,
                db.Check.recommendation,
                db.Check.checked_at,
                func.row_number().over(
                    partition_by=db.Check.domain,
                    order_by=db.Check.checked_at.desc(),
                ).label("rn"),
            )
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.checked_at >= cutoff)
            .subquery()
        )

        agg = (
            select(
                db.Check.domain.label("domain"),
                func.count().label("total"),
                func.sum(case((db.Check.recommendation == "block", 1), else_=0)).label("blocks"),
                func.sum(case((db.Check.recommendation == "verify_manually", 1), else_=0)).label("vm"),
                func.sum(case((db.Check.recommendation == "allow_with_flag", 1), else_=0)).label("awf"),
                func.sum(case((db.Check.recommendation == "allow", 1), else_=0)).label("allows"),
                func.max(db.Check.checked_at).label("last_seen"),
            )
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.checked_at >= cutoff)
            .group_by(db.Check.domain)
        )
        if q:
            agg = agg.where(db.Check.domain.ilike(f"%{q.strip().lower()}%"))
        agg_sub = agg.subquery()

        latest_only = select(latest_per_domain).where(latest_per_domain.c.rn == 1).subquery()

        stmt = (
            select(
                agg_sub.c.domain,
                agg_sub.c.total,
                agg_sub.c.blocks,
                agg_sub.c.vm,
                agg_sub.c.awf,
                agg_sub.c.allows,
                agg_sub.c.last_seen,
                latest_only.c.recommendation.label("last_rec"),
            )
            .select_from(agg_sub.join(latest_only, agg_sub.c.domain == latest_only.c.domain))
        )
        if recommendation is not None:
            stmt = stmt.where(latest_only.c.recommendation == recommendation)

        # Total count (for pagination) before applying limit/offset
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count = (await s.execute(count_stmt)).scalar_one() or 0

        stmt = stmt.order_by(agg_sub.c.last_seen.desc()).limit(limit).offset(offset)
        rows = (await s.execute(stmt)).all()

    # Annotate with custom-list membership in one Redis pipeline-ish pass.
    redis = get_redis()
    allow_set = set(await custom_lists.list_domains(redis, current.id, custom_lists.ALLOW))
    block_set = set(await custom_lists.list_domains(redis, current.id, custom_lists.BLOCK))

    items: list[DomainRow] = []
    for r in rows:
        in_allow = r.domain in allow_set
        in_block = r.domain in block_set
        if in_list == "allow" and not in_allow:
            continue
        if in_list == "block" and not in_block:
            continue
        if in_list == "none" and (in_allow or in_block):
            continue
        items.append(DomainRow(
            domain=r.domain,
            total=int(r.total or 0),
            breakdown=DomainBreakdown(
                blocks=int(r.blocks or 0),
                verify_manually=int(r.vm or 0),
                allow_with_flag=int(r.awf or 0),
                allows=int(r.allows or 0),
            ),
            last_seen=r.last_seen.isoformat() if r.last_seen else "",
            last_recommendation=r.last_rec or "",
            in_allow_list=in_allow,
            in_block_list=in_block,
        ))

    # Note: the `in_list` filter is applied post-query because list membership
    # lives in Redis. For typical sizes (< few hundred custom entries) this is
    # fine; if it becomes a hot path we can pre-filter the SQL with a CTE.
    return DomainsResponse(items=items, total=int(total_count))
