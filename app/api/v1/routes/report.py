"""
POST /v1/report

Customer feedback loop. Reports feed domain_stats counters and fuel the
auto-blocklist promotion pipeline — they do NOT immediately affect scoring.

Safeguards:
  - Per-key rate limit (hourly window)
  - Refuses to downgrade high-confidence blocklisted domains without manual
    review (prevents spoofing the feedback loop)
  - Returns review_sla_hours so callers know the report is queued, not applied
"""

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.v1.deps import require_api_key
from app.detection.layers.blocklist import HIGH_CONFIDENCE_THRESHOLD, REDIS_DOMAIN_KEY
from app.models.check import ReportRequest, ReportResponse
from app.models.errors import ErrorDetail, DOCS_BASE
from app.services import db, recorder
from app.services.redis_client import RedisClient, get_redis
from app.services.unkey import VerifyResult

logger = logging.getLogger(__name__)

router = APIRouter()

_THROWAWAY_REPORT_WEIGHT = 3
_REVIEW_SLA_HOURS = 4

# Per-key hourly rate limits on /v1/report. Free tier gets conservative limits
# to prevent feedback-loop spoofing; higher tiers get more headroom.
_REPORT_LIMITS: dict[str, int] = {
    "free": 10,
    "starter": 50,
    "growth": 200,
    "pro": 1000,
    "enterprise": 10_000,
}


async def _check_report_rate_limit(api_key_id: str, tier: str, redis: RedisClient) -> tuple[int, int]:
    """Returns (used, limit). Raises 429 when exceeded."""
    limit = _REPORT_LIMITS.get(tier, _REPORT_LIMITS["free"])
    key = f"report_rate:{api_key_id}:hourly"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)
    if count > limit:
        raise HTTPException(
            status_code=429,
            detail=ErrorDetail(
                code="report_rate_limit_exceeded",
                http_status=429,
                message=f"You've submitted {count - 1} of {limit} reports allowed per hour on the {tier} tier.",
                limit=limit,
                used=count - 1,
                upgrade_url="https://disposablecheck.com/pricing",
                docs_url=f"{DOCS_BASE}/report",
            ).model_dump(),
        )
    return count, limit


async def _is_high_confidence_disposable(domain: str, redis: RedisClient) -> bool:
    """True when the domain is on the curated blocklist above our HC threshold."""
    # Only check the base domain — subdomain stripping is the blocklist layer's job
    data = await redis.hgetall(REDIS_DOMAIN_KEY.format(domain))
    if not data or data.get("disposable") != "1":
        return False
    try:
        return float(data.get("confidence", "0")) >= HIGH_CONFIDENCE_THRESHOLD
    except ValueError:
        return False


def _report_id() -> str:
    return f"rpt_{secrets.token_hex(6)}"


@router.post("/report", response_model=ReportResponse, summary="Report a domain outcome")
async def report(
    request: Request,
    body: ReportRequest,
    auth: VerifyResult = Depends(require_api_key),
) -> ReportResponse:
    domain = body.domain.lower().strip()
    redis = get_redis()

    # ── Rate limit (raises 429) ──────────────────────────────────────────────
    await _check_report_rate_limit(auth.key_id, auth.tier, redis)

    # ── Anti-spoof: refuse downgrade of high-confidence blocklisted domains ─
    # A free-tier key cannot flag mailinator.com as "confirmed_legitimate" and
    # have it apply — such reports go to a manual review queue and do not
    # update the domain_stats counters.
    if body.outcome == "confirmed_legitimate" and await _is_high_confidence_disposable(domain, redis):
        logger.warning(
            "Key %s (%s tier) attempted to downgrade HC-blocklisted domain %s — flagged for review",
            auth.key_id, auth.tier, domain,
        )
        return ReportResponse(
            accepted=True,
            queued_for_review=True,
            review_sla_hours=48,  # longer SLA — this requires human review
            report_id=_report_id(),
            message=(
                "Report received and flagged for manual review. "
                "Downgrade requests on confirmed-disposable domains require human verification "
                "and additional corroborating reports."
            ),
        )

    report_id = _report_id()

    # ── Persist to DB for audit trail ────────────────────────────────────────
    try:
        async with db.get_session() as session:
            record = db.DomainReport(
                domain=domain,
                reporter_key_id=auth.key_id,
                outcome=body.outcome,
                notes=body.notes,
            )
            session.add(record)
            await session.commit()
    except Exception as exc:
        logger.error("Failed to persist domain report: %s", exc)

    # ── Bump domain_stats counters (feeds auto-blocklist promotion) ─────────
    await recorder.bump_report_counter(domain, body.outcome)

    # ── Update behavioral signals in Redis ───────────────────────────────────
    if body.outcome == "confirmed_throwaway":
        count_key = f"behavioral:{domain}:count"
        for _ in range(_THROWAWAY_REPORT_WEIGHT):
            await redis.incr(count_key)
        await redis.delete(f"result:v2:{domain}")
        logger.info("Domain %s confirmed throwaway by key %s (report %s)", domain, auth.key_id, report_id)

    elif body.outcome == "confirmed_legitimate":
        await redis.delete(f"result:v2:{domain}")
        logger.info("Domain %s confirmed legitimate by key %s (report %s)", domain, auth.key_id, report_id)

    return ReportResponse(
        accepted=True,
        queued_for_review=True,
        review_sla_hours=_REVIEW_SLA_HOURS,
        report_id=report_id,
        message=(
            "Report received and queued for review. "
            "It will feed domain_stats aggregates and may affect scoring once corroborated."
        ),
    )
