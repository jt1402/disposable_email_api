"""
Detection Engine — orchestrates all 5 layers and returns a unified CheckResponse.

Flow:
  1. Syntax (sync, ~1ms)         — fail fast if malformed
  2. Blocklist (Redis, ~2ms)     — cache hit returns immediately
  3. DNS intelligence (~50-200ms) — MX + WHOIS + cluster
  4. Behavioral (Redis, ~2ms)    — traffic pattern signals
  5. Catch-all (SMTP, ~500ms)    — Pro/Enterprise tier only

Full result is cached in Redis (TTL 24h) keyed by normalised domain.
"""

import asyncio
import json
import logging
import time

from app.core.config import get_settings
from app.detection import scorer
from app.detection.layers import behavioral, blocklist, catchall, dns_intel, syntax
from app.models.check import CheckResponse, Recommendation, RiskLevel
from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_RESULT_CACHE_TTL = 86_400  # 24h — domain classification rarely changes day-to-day
_RESULT_CACHE_KEY = "result:{}"


async def check(
    email: str,
    redis: RedisClient,
    api_key_id: str = "",
    tier: str = "free",
) -> CheckResponse:
    settings = get_settings()
    t_start = time.monotonic()

    # ── Layer 1: Syntax (no I/O) ──────────────────────────────────────────────
    syn = syntax.validate(email)
    if not syn.valid:
        elapsed = int((time.monotonic() - t_start) * 1000)
        return CheckResponse(
            email=email,
            valid_syntax=False,
            disposable=False,
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            signals=["invalid_syntax"],
            recommendation=Recommendation.BLOCK,
            cached=False,
            latency_ms=elapsed,
        )

    domain = syn.domain
    all_signals: list[str] = list(syn.signals)

    # ── Full result cache (keyed by normalised domain) ────────────────────────
    cache_key = _RESULT_CACHE_KEY.format(domain)
    cached_raw = await redis.get(cache_key)
    if cached_raw:
        data = json.loads(cached_raw)
        # Reconstruct response — override email/latency since those are per-request
        elapsed = int((time.monotonic() - t_start) * 1000)
        # Record behavioral signal even on cache hit
        if api_key_id:
            asyncio.ensure_future(behavioral.record_query(domain, api_key_id, redis))
        return CheckResponse(
            email=email,
            valid_syntax=data["valid_syntax"],
            disposable=data["disposable"],
            risk_score=data["risk_score"],
            risk_level=RiskLevel(data["risk_level"]),
            catch_all=data.get("catch_all"),
            domain_age_days=data.get("domain_age_days"),
            mx_shared_with_known_disposables=data.get("mx_shared_with_known_disposables", False),
            signals=data["signals"],
            recommendation=Recommendation(data["recommendation"]),
            cached=True,
            latency_ms=elapsed,
        )

    # ── Layers 2, 3, 4 in parallel ───────────────────────────────────────────
    bl_task = asyncio.create_task(blocklist.check(domain, redis))
    dns_task = asyncio.create_task(dns_intel.check(domain, redis))
    beh_task = asyncio.create_task(behavioral.check(domain, redis))

    bl_result, dns_result, beh_result = await asyncio.gather(
        bl_task, dns_task, beh_task, return_exceptions=True
    )

    # Gracefully handle partial failures — don't let one layer kill the response
    if isinstance(bl_result, Exception):
        logger.warning("Blocklist layer error for %s: %s", domain, bl_result)
        bl_result = blocklist.BlocklistResult()
    if isinstance(dns_result, Exception):
        logger.warning("DNS layer error for %s: %s", domain, dns_result)
        dns_result = dns_intel.DnsResult()
    if isinstance(beh_result, Exception):
        logger.warning("Behavioral layer error for %s: %s", domain, beh_result)
        beh_result = behavioral.BehavioralResult()

    all_signals += bl_result.signals + dns_result.signals + beh_result.signals

    # ── Layer 5: Catch-all (Pro/Enterprise, opt-in) ───────────────────────────
    catch_all_value: bool | None = None
    if (
        settings.catchall_enabled
        and tier in ("pro", "enterprise")
        and dns_result.has_mx
    ):
        ca_result = await catchall.check(domain, dns_result.mx_hosts, redis, settings.smtp_timeout)
        all_signals += ca_result.signals
        catch_all_value = ca_result.is_catch_all

    # ── Score aggregation ─────────────────────────────────────────────────────
    risk_score = scorer.compute(all_signals)
    risk_lvl = scorer.risk_level(risk_score)
    recommendation = scorer.recommendation(risk_score)
    is_disposable = risk_score >= 50

    # ── Record behavioral data ────────────────────────────────────────────────
    if api_key_id:
        asyncio.ensure_future(behavioral.record_query(domain, api_key_id, redis))

    # ── Cache the domain result ───────────────────────────────────────────────
    cache_payload = {
        "valid_syntax": True,
        "disposable": is_disposable,
        "risk_score": risk_score,
        "risk_level": risk_lvl.value,
        "catch_all": catch_all_value,
        "domain_age_days": dns_result.domain_age_days,
        "mx_shared_with_known_disposables": dns_result.mx_shared_with_disposables,
        "signals": all_signals,
        "recommendation": recommendation.value,
    }
    await redis.setex(cache_key, _RESULT_CACHE_TTL, json.dumps(cache_payload))

    elapsed = int((time.monotonic() - t_start) * 1000)
    return CheckResponse(
        email=email,
        valid_syntax=True,
        disposable=is_disposable,
        risk_score=risk_score,
        risk_level=risk_lvl,
        catch_all=catch_all_value,
        domain_age_days=dns_result.domain_age_days,
        mx_shared_with_known_disposables=dns_result.mx_shared_with_disposables,
        signals=all_signals,
        recommendation=recommendation,
        cached=False,
        latency_ms=elapsed,
    )
