"""
Usage dashboard endpoints.

All queries are scoped to the caller's API keys. We look up the Unkey key_ids
owned by the user, then aggregate `checks` rows whose `api_key_id` column
matches. If the user has no keys, responses are empty (not an error).
"""

from datetime import UTC, datetime, timedelta

import json

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select

from app.api.v1.deps import CurrentUser, require_api_key
from app.services import credits, custom_lists, db
from app.services.redis_client import get_redis
from app.services.unkey import VerifyResult

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
    allow_with_flag: int
    allows: int
    avg_latency_ms: float
    cache_hit_rate: float


async def _build_summary(user_id: int) -> UsageSummary:
    """Shared summary builder used by both session and API-key paths."""
    key_ids = await _key_ids_for_user(user_id)
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
            allow_with_flag=int(row.awf or 0),
            allows=int(row.allows or 0),
            avg_latency_ms=float(row.avg_latency or 0.0),
            cache_hit_rate=(cached_count / n) if n > 0 else 0.0,
        )


@router.get("/summary", response_model=UsageSummary)
async def usage_summary(current: CurrentUser) -> UsageSummary:
    """
    Rolled-up usage stats for the caller. Period = current calendar month
    (matches Unkey's monthly refill day). `checks_this_period` is what the
    dashboard's quota bar reads from.
    """
    return await _build_summary(current.id)


class MeUsageResponse(UsageSummary):
    credit_balance_checks: int = 0


@router.get(
    "/me",
    response_model=MeUsageResponse,
    summary="Usage summary for the caller (API-key authed)",
)
async def me_usage(
    auth: VerifyResult = Depends(require_api_key),
) -> MeUsageResponse:
    """
    Programmatic equivalent of /v1/usage/summary — same shape plus the
    customer's remaining credit balance. Use this from your own admin /
    monitoring stack rather than scraping the dashboard.
    """
    if not auth.owner_id.isdigit():
        raise HTTPException(status_code=400, detail={
            "code": "invalid_key_owner",
            "message": "This key is not bound to a customer account.",
        })
    owner_id = int(auth.owner_id)
    summary = await _build_summary(owner_id)
    balance = await credits.get_balance(owner_id)
    return MeUsageResponse(
        **summary.model_dump(),
        credit_balance_checks=balance,
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
    next_cursor: str | None = None


@router.get("/recent", response_model=RecentResponse)
async def recent_checks(
    current: CurrentUser,
    limit: int = Query(default=50, ge=1, le=500),
    before: str | None = Query(
        default=None,
        description="ISO-8601 timestamp from a previous response's next_cursor. "
                    "Returns rows strictly older than this time.",
    ),
) -> RecentResponse:
    """
    Latest N checks across all of the user's keys. Domain only — no emails.
    Cursor pagination: pass `before` set to the prior response's next_cursor
    to fetch the next page backward through history.
    """
    key_ids = await _key_ids_for_user(current.id)
    before_dt: datetime | None = None
    if before:
        try:
            before_dt = datetime.fromisoformat(before.replace("Z", "+00:00"))
        except ValueError:
            before_dt = None

    async with db.get_session() as s:
        stmt = (
            select(db.Check)
            .where(db.Check.api_key_id.in_(key_ids))
            .order_by(db.Check.checked_at.desc())
            # Fetch one extra row to detect "has more" without a separate count.
            .limit(limit + 1)
        )
        if before_dt is not None:
            stmt = stmt.where(db.Check.checked_at < before_dt)
        rows = (await s.execute(stmt)).scalars().all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = rows[-1].checked_at.isoformat() if has_more and rows else None

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
        ],
        next_cursor=next_cursor,
    )


# ── Domain Activity (per-user, aggregated) ──────────────────────────────────

class DomainBreakdown(BaseModel):
    blocks: int
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


class DomainsCounts(BaseModel):
    need_review: int
    blocked: int
    trusted: int


class DomainsResponse(BaseModel):
    items: list[DomainRow]
    total: int
    counts: DomainsCounts


_REC_VALUES = ("allow", "allow_with_flag", "block")


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
                allow_with_flag=int(r.awf or 0),
                allows=int(r.allows or 0),
            ),
            last_seen=r.last_seen.isoformat() if r.last_seen else "",
            last_recommendation=r.last_rec or "",
            in_allow_list=in_allow,
            in_block_list=in_block,
        ))

    # Counts for the page header pills. need_review = domains whose latest
    # verdict is allow_with_flag, scoped to the same window, excluding any
    # domain already on a custom list or marked reviewed.
    reviewed_set = set(await custom_lists.list_domains(redis, current.id, custom_lists.REVIEWED))
    async with db.get_session() as s:
        nr_stmt = (
            select(func.count())
            .select_from(
                select(latest_per_domain)
                .where(latest_per_domain.c.rn == 1)
                .where(latest_per_domain.c.recommendation == "allow_with_flag")
                .subquery()
            )
        )
        # Subtract reviewed/allow/block domains from the flagged count.
        # Cheap because the overlap sets are small.
        vm_total = (await s.execute(nr_stmt)).scalar_one() or 0
    excluded = reviewed_set | allow_set | block_set
    if excluded:
        vm_excl_stmt = (
            select(func.count())
            .select_from(
                select(latest_per_domain)
                .where(latest_per_domain.c.rn == 1)
                .where(latest_per_domain.c.recommendation == "allow_with_flag")
                .where(latest_per_domain.c.domain.in_(excluded))
                .subquery()
            )
        )
        async with db.get_session() as s:
            vm_overlap = (await s.execute(vm_excl_stmt)).scalar_one() or 0
        need_review = max(0, int(vm_total) - int(vm_overlap))
    else:
        need_review = int(vm_total)

    # Note: the `in_list` filter is applied post-query because list membership
    # lives in Redis. For typical sizes (< few hundred custom entries) this is
    # fine; if it becomes a hot path we can pre-filter the SQL with a CTE.
    return DomainsResponse(
        items=items,
        total=int(total_count),
        counts=DomainsCounts(
            need_review=need_review,
            blocked=len(block_set),
            trusted=len(allow_set),
        ),
    )


# ── Per-domain drawer (history + aggregate + most-recent signals) ───────────

class HistoryRow(BaseModel):
    checked_at: str
    recommendation: str
    risk_score: int
    risk_level: str | None
    confidence_level: str | None
    disposable: bool | None
    latency_ms: int
    cached: bool
    path_taken: str


class SignalEntry(BaseModel):
    name: str
    direction: str
    weight: int
    description: str


class DomainHistoryResponse(BaseModel):
    domain: str
    history: list[HistoryRow]
    aggregate: DomainBreakdown
    total: int
    in_allow_list: bool
    in_block_list: bool
    is_reviewed: bool
    # Last verdict's signals — read from the per-domain Redis cache. Best
    # source we have for "why did this fire" without persisting signals
    # alongside every check row.
    last_signals_fired: list[SignalEntry]
    last_signals_trust: list[SignalEntry]


@router.get("/domains/{domain}/history", response_model=DomainHistoryResponse)
async def domain_history(
    current: CurrentUser,
    domain: str = Path(..., max_length=255),
    limit: int = Query(default=20, ge=1, le=100),
) -> DomainHistoryResponse:
    """
    History + aggregate + last-verdict signals for one domain. Powers the
    drawer on the Domain Activity page.
    """
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=422, detail={"code": "invalid_domain", "message": "Empty domain."})

    key_ids = await _key_ids_for_user(current.id)

    async with db.get_session() as s:
        history_stmt = (
            select(db.Check)
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.domain == domain)
            .order_by(db.Check.checked_at.desc())
            .limit(limit)
        )
        history_rows = (await s.execute(history_stmt)).scalars().all()

        agg_stmt = (
            select(
                func.count().label("total"),
                func.sum(case((db.Check.recommendation == "block", 1), else_=0)).label("blocks"),
                func.sum(case((db.Check.recommendation == "allow_with_flag", 1), else_=0)).label("awf"),
                func.sum(case((db.Check.recommendation == "allow", 1), else_=0)).label("allows"),
            )
            .where(db.Check.api_key_id.in_(key_ids))
            .where(db.Check.domain == domain)
        )
        agg_row = (await s.execute(agg_stmt)).one()

    redis = get_redis()
    in_allow = await redis.sismember(f"custom:allow:{current.id}", domain)
    in_block = await redis.sismember(f"custom:block:{current.id}", domain)
    is_reviewed = await redis.sismember(f"reviewed:{current.id}", domain)

    fired: list[SignalEntry] = []
    trust: list[SignalEntry] = []
    cached_raw = await redis.get(f"result:v2:{domain}")
    if cached_raw:
        try:
            data = json.loads(cached_raw)
            for s_obj in data.get("signals", {}).get("fired", []):
                fired.append(SignalEntry(
                    name=s_obj.get("name", ""),
                    direction=s_obj.get("direction", "risk"),
                    weight=int(s_obj.get("weight", 0)),
                    description=s_obj.get("description", ""),
                ))
            for s_obj in data.get("signals", {}).get("trust_signals", []):
                trust.append(SignalEntry(
                    name=s_obj.get("name", ""),
                    direction=s_obj.get("direction", "trust"),
                    weight=int(s_obj.get("weight", 0)),
                    description=s_obj.get("description", ""),
                ))
        except (ValueError, TypeError):
            pass

    return DomainHistoryResponse(
        domain=domain,
        history=[
            HistoryRow(
                checked_at=r.checked_at.isoformat(),
                recommendation=r.recommendation,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                confidence_level=r.confidence_level,
                disposable=r.disposable,
                latency_ms=r.latency_ms,
                cached=r.cached,
                path_taken=r.path_taken,
            )
            for r in history_rows
        ],
        aggregate=DomainBreakdown(
            blocks=int(agg_row.blocks or 0),
            allow_with_flag=int(agg_row.awf or 0),
            allows=int(agg_row.allows or 0),
        ),
        total=int(agg_row.total or 0),
        in_allow_list=in_allow,
        in_block_list=in_block,
        is_reviewed=is_reviewed,
        last_signals_fired=fired,
        last_signals_trust=trust,
    )
