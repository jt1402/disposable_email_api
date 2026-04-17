"""
Fire-and-forget persistence for check events.

Every /v1/check request results in:
  1. One INSERT into `checks` (append-only audit log)
  2. One UPSERT into `domain_stats` (atomic counter + running-average update)

Designed to never raise into the request handler — caller uses
asyncio.ensure_future(record_check(...)) so latency is unaffected.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.services import db

logger = logging.getLogger(__name__)


async def record_check(
    api_key_id: str,
    domain: str,
    risk_score: int,
    recommendation: str,
    path_taken: str,
    cached: bool,
    latency_ms: int,
) -> None:
    """
    Write one Check row and upsert DomainStats counters.

    Never raises — logs on failure. Safe to call from asyncio.ensure_future.
    Skipped entirely in dev mode when api_key_id is 'dev' (optional: set to "
    log those too — useful for local testing of the pipeline).
    """
    if not domain:
        return

    try:
        now = datetime.now(timezone.utc)

        async with db.get_session() as session:
            # ── 1. Append to checks log ─────────────────────────────────────
            check = db.Check(
                api_key_id=api_key_id or "anonymous",
                domain=domain,
                risk_score=risk_score,
                recommendation=recommendation,
                path_taken=path_taken,
                cached=cached,
                latency_ms=latency_ms,
                checked_at=now,
            )
            session.add(check)

            # ── 2. Upsert domain_stats ──────────────────────────────────────
            # Postgres ON CONFLICT DO UPDATE: atomic counter bump + running
            # average. Running avg formula:
            #   new_avg = (old_avg * old_total + new_score) / (old_total + 1)
            stmt = pg_insert(db.DomainStats).values(
                domain=domain,
                first_seen=now,
                last_seen=now,
                total_checks=1,
                blocks=1 if recommendation == "block" else 0,
                verify_manually=1 if recommendation == "verify_manually" else 0,
                allow_with_flag=1 if recommendation == "allow_with_flag" else 0,
                allows=1 if recommendation == "allow" else 0,
                avg_score=float(risk_score),
                last_recommendation=recommendation,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["domain"],
                set_={
                    "last_seen": now,
                    "total_checks": db.DomainStats.total_checks + 1,
                    "blocks": db.DomainStats.blocks + (1 if recommendation == "block" else 0),
                    "verify_manually": db.DomainStats.verify_manually + (1 if recommendation == "verify_manually" else 0),
                    "allow_with_flag": db.DomainStats.allow_with_flag + (1 if recommendation == "allow_with_flag" else 0),
                    "allows": db.DomainStats.allows + (1 if recommendation == "allow" else 0),
                    "avg_score": (
                        (db.DomainStats.avg_score * db.DomainStats.total_checks + risk_score)
                        / (db.DomainStats.total_checks + 1)
                    ),
                    "last_recommendation": recommendation,
                },
            )
            await session.execute(stmt)
            await session.commit()

    except Exception as exc:
        logger.warning("record_check failed for %s: %s", domain, exc)


async def bump_report_counter(domain: str, outcome: str) -> None:
    """
    Called from /v1/report. Bumps reports_throwaway / reports_legitimate on
    domain_stats. If the domain has never been checked, creates a row for it.

    outcome: 'confirmed_throwaway' | 'confirmed_legitimate' | 'suspected_throwaway'
    """
    try:
        now = datetime.now(timezone.utc)
        throwaway = 1 if outcome in ("confirmed_throwaway", "suspected_throwaway") else 0
        legitimate = 1 if outcome == "confirmed_legitimate" else 0

        async with db.get_session() as session:
            stmt = pg_insert(db.DomainStats).values(
                domain=domain,
                first_seen=now,
                last_seen=now,
                reports_throwaway=throwaway,
                reports_legitimate=legitimate,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["domain"],
                set_={
                    "reports_throwaway": db.DomainStats.reports_throwaway + throwaway,
                    "reports_legitimate": db.DomainStats.reports_legitimate + legitimate,
                    "last_seen": now,
                },
            )
            await session.execute(stmt)
            await session.commit()

    except Exception as exc:
        logger.warning("bump_report_counter failed for %s: %s", domain, exc)


# ── Read helpers (for dashboards + the future promotion cron) ────────────────

async def get_domain_stats(domain: str) -> db.DomainStats | None:
    async with db.get_session() as session:
        result = await session.execute(
            select(db.DomainStats).where(db.DomainStats.domain == domain)
        )
        return result.scalar_one_or_none()


async def count_unique_customers_for_domain(domain: str, days: int = 30) -> int:
    """Customers who queried this domain in the last N days."""
    async with db.get_session() as session:
        cutoff = datetime.now(timezone.utc).replace(microsecond=0)
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=days)
        result = await session.execute(
            select(func.count(func.distinct(db.Check.api_key_id)))
            .where(db.Check.domain == domain)
            .where(db.Check.checked_at >= cutoff)
        )
        return result.scalar_one() or 0
