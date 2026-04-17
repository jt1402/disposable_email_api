"""
POST /v1/report

Customer feedback loop — when a customer confirms a domain was throwaway or legitimate,
that signal feeds back into the behavioral scoring model.
Customers become involuntary data contributors.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.v1.deps import require_api_key
from app.models.check import ReportRequest, ReportResponse
from app.services import db, recorder
from app.services.redis_client import get_redis
from app.services.unkey import VerifyResult

logger = logging.getLogger(__name__)

router = APIRouter()

# How much a confirmed_throwaway report boosts the behavioral score
_THROWAWAY_REPORT_WEIGHT = 3


@router.post("/report", response_model=ReportResponse, summary="Report a domain outcome")
async def report(
    body: ReportRequest,
    auth: VerifyResult = Depends(require_api_key),
) -> ReportResponse:
    domain = body.domain.lower().strip()
    redis = get_redis()

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

    # ── Bump domain_stats report counters (feeds auto-blocklist promotion) ──
    await recorder.bump_report_counter(domain, body.outcome)

    # ── Update behavioral signals in Redis ───────────────────────────────────
    if body.outcome == "confirmed_throwaway":
        # Amplify the behavioral count signal — treat each report as N queries
        count_key = f"behavioral:{domain}:count"
        for _ in range(_THROWAWAY_REPORT_WEIGHT):
            await redis.incr(count_key)

        # Bust the result cache so next check runs fresh
        await redis.delete(f"result:v2:{domain}")  # invalidate

        logger.info("Domain %s confirmed throwaway by key %s", domain, auth.key_id)

    elif body.outcome == "confirmed_legitimate":
        # Clear any cached result so the domain gets a fresh check
        await redis.delete(f"result:v2:{domain}")

        logger.info("Domain %s confirmed legitimate by key %s", domain, auth.key_id)

    return ReportResponse(accepted=True, message="Report received. Thank you.")
