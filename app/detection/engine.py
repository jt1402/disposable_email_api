"""
Detection Engine — orchestrates all 5 layers and assembles the 5-block response.

Flow:
  1. Syntax (sync, ~1ms)            — fail fast if malformed
  2. Blocklist + DNS + Behavioral   — parallel, 50-200ms
  3. Catch-all (feature-gated)      — optional, ~500ms, off by default
  4. Compound-signal promotion      — catch_all + new_domain → catch_all_new_domain
  5. Score + confidence + profile   — produce breakdown, recommendation, summary
  6. Build 5-block CheckResponse

Cache key is versioned (result:v2:) because the response shape changed.
"""

import asyncio
import json
import logging
import secrets
import time
from datetime import UTC, datetime

from app.core.config import get_settings
from app.detection import scorer
from app.detection.layers import behavioral, blocklist, catchall, dns_intel, syntax
from app.services import recorder
from app.models.check import (
    CatchAllDetail,
    Check,
    CheckResponse,
    Checks,
    Compounding,
    Meta,
    ModelPhase,
    RiskProfile,
    Score,
    ScoreComponents,
    Signal,
    SignalDirection,
    Signals,
    Thresholds,
    Verdict,
)
from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_RESULT_CACHE_TTL_FRAUD = 86_400 * 7     # confirmed fraud — 7 days
_RESULT_CACHE_TTL_TRUSTED = 86_400 * 3   # trusted — 3 days (verify often)
_RESULT_CACHE_TTL_AMBIGUOUS = 86_400     # 1 day
_RESULT_CACHE_TTL_NEW_DOMAIN = 3600 * 4  # 4 hours — new domains change fast
_RESULT_CACHE_KEY = "result:v2:{}"


def _generate_request_id() -> str:
    return f"req_{secrets.token_hex(6)}"


def _record_async(api_key_id: str, response: CheckResponse) -> None:
    """Fire-and-forget persistence. Never blocks the response."""
    if not response.meta.domain:
        return
    asyncio.ensure_future(recorder.record_check(
        api_key_id=api_key_id,
        domain=response.meta.domain,
        risk_score=response.score.value,
        recommendation=response.verdict.recommendation.value,
        path_taken=response.meta.path_taken,
        cached=response.meta.cached,
        latency_ms=response.meta.latency_ms,
    ))


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _resolve_profile(requested: str | None, default: str) -> RiskProfile:
    """Header → explicit → default. Invalid values fall back to default."""
    candidates = [requested, default, "balanced"]
    for c in candidates:
        if not c:
            continue
        c = c.strip().lower()
        try:
            return RiskProfile(c)
        except ValueError:
            continue
    return RiskProfile.BALANCED


def _promote_compound_signals(signal_names: list[str]) -> list[str]:
    """
    Named compounds are qualitatively stronger than their parts. Replace
    components with the compound to avoid double-counting.

    Also strips age-based trust signals when a homograph is detected — even
    if WHOIS somehow resolved against the lookalike, the attacker should
    never earn age trust for impersonating a legit domain.

    Current compounds:
      catch_all_domain + (new_domain_30d | domain_age_under_7_days)
        → catch_all_new_domain  (removes catch_all_domain + the age signal)
    """
    s = list(signal_names)
    new_domain_age_signals = {"new_domain_30d", "domain_age_under_7_days"}
    if "catch_all_domain" in s and any(x in s for x in new_domain_age_signals):
        s = [x for x in s if x != "catch_all_domain" and x not in new_domain_age_signals]
        s.append("catch_all_new_domain")

    # Belt-and-braces against homograph + age-trust exploit: any age-based
    # trust / new-domain signal accompanying a homograph detection is
    # automatically suspect — the WHOIS lookup may have resolved against
    # the lookalike domain. Drop them.
    if "unicode_homograph_domain" in s:
        homograph_suppressed = {
            "domain_age_over_5_years",
            "domain_age_over_2_years",
            "mx_known_legitimate_host",  # MX may also mimic the target
        }
        s = [x for x in s if x not in homograph_suppressed]

    return s


def _pick_cache_ttl(score: int, has_new_domain: bool, fraud_confirmed: bool, trusted: bool) -> int:
    if trusted:
        return _RESULT_CACHE_TTL_TRUSTED
    if has_new_domain:
        return _RESULT_CACHE_TTL_NEW_DOMAIN
    if fraud_confirmed or score >= 90:
        return _RESULT_CACHE_TTL_FRAUD
    return _RESULT_CACHE_TTL_AMBIGUOUS


_KNOWN_DISPOSABLE_SIGNALS: frozenset[str] = frozenset({
    "known_disposable_domain",
    "known_disposable_domain_high_confidence",
})


def _is_disposable(signal_names: list[str]) -> bool:
    """
    Only true when the engine matched a blocklist entry. `no_mx_records`,
    `invalid_syntax`, and `domain_does_not_exist` are deliverability problems,
    not evidence the domain is a disposable email provider.
    """
    return any(s in _KNOWN_DISPOSABLE_SIGNALS for s in signal_names)


def _is_valid_address(syntax_ok: bool, has_mx: bool | None) -> bool:
    """
    True only when syntax passes AND the domain has MX records. has_mx=None
    means the DNS check didn't run or was inconclusive — treat as not-valid
    rather than assume.
    """
    return bool(syntax_ok and has_mx)


def _signals_to_objects(signal_names: list[str]) -> tuple[list[Signal], list[Signal]]:
    """Convert signal name strings into Signal Pydantic objects using the registry."""
    fired: list[Signal] = []
    trust: list[Signal] = []
    for name in signal_names:
        sd = scorer.get_signal_def(name)
        if not sd:
            continue
        direction = SignalDirection.TRUST if sd.tier == scorer.TIER_TRUST else SignalDirection.RISK
        sig = Signal(
            name=sd.name,
            category=sd.category,
            direction=direction,
            weight=sd.weight,
            description=sd.description,
        )
        if direction == SignalDirection.TRUST:
            trust.append(sig)
        else:
            fired.append(sig)
    return fired, trust


def _build_hard_disqualifier_response(
    request_id: str,
    email: str,
    domain: str,
    disqualifier: str,
    t_start: float,
    profile: RiskProfile,
    phase: ModelPhase,
    settings,
    path_taken: str = "fast",
    extra_checks: list[Check] | None = None,
    dns_has_mx: bool | None = None,
) -> CheckResponse:
    elapsed = int((time.monotonic() - t_start) * 1000)
    th = scorer.thresholds_for(profile, phase)

    fired, trust = _signals_to_objects([disqualifier])
    syntax_ok = disqualifier != "invalid_syntax"

    return CheckResponse(
        meta=Meta(
            request_id=request_id,
            email=email,
            domain=domain,
            checked_at=_now_iso(),
            latency_ms=elapsed,
            model_phase=phase,
            model_version=settings.model_version,
            path_taken=path_taken,
            cached=False,
        ),
        verdict=Verdict(
            recommendation=scorer.Recommendation.BLOCK,
            risk_level=scorer.RiskLevel.CRITICAL,
            disposable=_is_disposable([disqualifier]),
            catch_all=None,
            catch_all_checked=False,
            valid_address=_is_valid_address(syntax_ok, dns_has_mx),
            safe_to_send=False,
            summary=scorer.build_summary(
                [disqualifier], [], 100, scorer.Recommendation.BLOCK,
            ),
        ),
        score=Score(
            value=100,
            confidence=1.0,
            confidence_level=scorer.ConfidenceLevel.HIGH,
            components=ScoreComponents(
                strong_signals=0, corroborating=0, trust_adjustments=0,
                compounding_bonus=0, final_clamped=100,
            ),
            thresholds=Thresholds(
                block_at=th.block, flag_at=th.flag, your_profile=profile,
            ),
            catch_all_detail=None,
        ),
        signals=Signals(
            fired=fired,
            trust_signals=trust,
            compounding=Compounding(
                applied=False, signal_count=0, bonus_applied=0,
                explanation="Hard disqualifier — no further signals evaluated.",
            ),
        ),
        checks=Checks(
            run=extra_checks or [Check(
                name="syntax_validation",
                status="failed" if disqualifier == "invalid_syntax" else "passed",
                duration_ms=elapsed,
                result=disqualifier,
            )],
            path_explanation=f"Hard disqualifier '{disqualifier}' — fast-path exit.",
        ),
    )


async def check(
    email: str,
    redis: RedisClient,
    api_key_id: str = "",
    risk_profile_header: str | None = None,
    request_id: str | None = None,
) -> CheckResponse:
    settings = get_settings()
    t_start = time.monotonic()
    request_id = request_id or _generate_request_id()

    try:
        phase = ModelPhase(settings.model_phase)
    except ValueError:
        phase = ModelPhase.BOOTSTRAP

    profile = _resolve_profile(risk_profile_header, settings.default_risk_profile)
    thresholds = scorer.thresholds_for(profile, phase)

    # ── Layer 1: Syntax ─────────────────────────────────────────────────────
    syn = syntax.validate(email)
    if not syn.valid:
        return _build_hard_disqualifier_response(
            request_id=request_id,
            email=email,
            domain="",
            disqualifier="invalid_syntax",
            t_start=t_start,
            profile=profile,
            phase=phase,
            settings=settings,
        )

    domain = syn.domain
    syn_signals: list[str] = list(syn.signals)

    # ── Full-result cache short-circuit (fast path for known domains) ───────
    cache_key = _RESULT_CACHE_KEY.format(domain)
    cached_raw = await redis.get(cache_key)
    if cached_raw:
        try:
            data = json.loads(cached_raw)
            response = _rehydrate_cached_response(
                data, email, domain, request_id, t_start, phase, profile, thresholds, settings,
            )
            if api_key_id:
                asyncio.ensure_future(behavioral.record_query(domain, api_key_id, redis))
            _record_async(api_key_id, response)
            return response
        except (ValueError, TypeError, KeyError) as exc:
            logger.debug("Cache rehydrate failed for %s: %s — falling through", domain, exc)

    # ── Layers 2, 3, 4 in parallel ──────────────────────────────────────────
    bl_task = asyncio.create_task(blocklist.check(domain, redis))
    dns_task = asyncio.create_task(dns_intel.check(domain, redis))
    beh_task = asyncio.create_task(behavioral.check(domain, redis))
    bl_result, dns_result, beh_result = await asyncio.gather(
        bl_task, dns_task, beh_task, return_exceptions=True,
    )

    if isinstance(bl_result, Exception):
        logger.warning("Blocklist layer error for %s: %s", domain, bl_result)
        bl_result = blocklist.BlocklistResult()
    if isinstance(dns_result, Exception):
        logger.warning("DNS layer error for %s: %s", domain, dns_result)
        dns_result = dns_intel.DnsResult()
    if isinstance(beh_result, Exception):
        logger.warning("Behavioral layer error for %s: %s", domain, beh_result)
        beh_result = behavioral.BehavioralResult()

    all_signal_names: list[str] = syn_signals + bl_result.signals + dns_result.signals + beh_result.signals
    confidence_penalties: list[str] = list(dns_result.confidence_penalties) + list(beh_result.confidence_penalties)

    check_records: list[dict] = []
    check_records.append({
        "name": "syntax_validation", "status": "passed", "duration_ms": 0.1, "result": None, "probe_detail": None,
    })
    check_records.append({
        "name": "blocklist_lookup",
        "status": "checked", "duration_ms": 1.0,
        "result": "hit" if bl_result.hit else ("trusted" if bl_result.is_trusted_provider else "miss"),
        "probe_detail": None,
    })
    for c in dns_result.checks:
        check_records.append({
            "name": c.name, "status": c.status, "duration_ms": c.duration_ms,
            "result": c.result, "probe_detail": c.probe_detail,
        })
    for c in beh_result.checks:
        check_records.append({
            "name": c.name, "status": c.status, "duration_ms": c.duration_ms,
            "result": c.result, "probe_detail": c.probe_detail,
        })

    # ── Hard disqualifier check (no_mx_records is the main runtime one) ─────
    for name in all_signal_names:
        if scorer.is_hard_disqualifier(name):
            # Record behavioral history
            if api_key_id:
                asyncio.ensure_future(behavioral.record_query(domain, api_key_id, redis))
            extra_checks = [Check(**c) for c in check_records]
            response = _build_hard_disqualifier_response(
                request_id=request_id, email=email, domain=domain,
                disqualifier=name, t_start=t_start, profile=profile, phase=phase,
                settings=settings, path_taken="standard", extra_checks=extra_checks,
                dns_has_mx=dns_result.has_mx,
            )
            await _cache_response(redis, cache_key, response, has_new_domain=False, fraud=True, trusted=False)
            _record_async(api_key_id, response)
            return response

    # ── Layer 5: Catch-all (feature-gated) ──────────────────────────────────
    ca_result: catchall.CatchAllResult | None = None
    catch_all_value: bool | None = None
    catch_all_probability = 0.0
    path_taken = "standard"
    if settings.catchall_enabled and dns_result.has_mx:
        ca_result = await catchall.check(domain, dns_result.mx_hosts, redis, settings.smtp_timeout)
        all_signal_names += ca_result.signals
        confidence_penalties += ca_result.confidence_penalties
        catch_all_value = ca_result.is_catch_all
        catch_all_probability = ca_result.probability
        for c in ca_result.checks:
            check_records.append({
                "name": c.name, "status": c.status, "duration_ms": c.duration_ms,
                "result": c.result, "probe_detail": c.probe_detail,
            })
        path_taken = "deep"
    elif dns_result.has_mx and not settings.catchall_enabled:
        confidence_penalties.append("catchall_skipped")

    # ── Special case: old-established catch-all is a trust signal ───────────
    if catch_all_value and dns_result.domain_age_days and dns_result.domain_age_days >= 5 * 365:
        all_signal_names.append("catch_all_old_established")

    # ── Promote compound signals ────────────────────────────────────────────
    all_signal_names = _promote_compound_signals(all_signal_names)

    # ── Deduplicate while preserving order ──────────────────────────────────
    seen: set[str] = set()
    deduped: list[str] = []
    for name in all_signal_names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    all_signal_names = deduped

    # ── Score breakdown ─────────────────────────────────────────────────────
    breakdown = scorer.compute_breakdown(all_signal_names)
    confidence = scorer.calculate_confidence(confidence_penalties)
    conf_level = scorer.confidence_level(confidence)

    rec = scorer.derive_recommendation(
        breakdown.final_clamped, confidence, all_signal_names, thresholds,
    )
    rlvl = scorer.risk_level(breakdown.final_clamped)

    # ── Build response ──────────────────────────────────────────────────────
    fired_objs, trust_objs = _signals_to_objects(all_signal_names)

    corroborating_count = sum(
        1 for name in all_signal_names
        if (sd := scorer.get_signal_def(name)) and sd.tier == scorer.TIER_CORROBORATING
    )

    catch_all_detail = None
    if ca_result is not None and ca_result.checked:
        legitimate_use_likely = (
            catch_all_value is True
            and dns_result.domain_age_days is not None
            and dns_result.domain_age_days >= 2 * 365
            and dns_result.has_spf is True
        )
        ca_type = (
            "confirmed" if catch_all_value is True
            else "cleared" if catch_all_value is False
            else "suspected"
        )
        catch_all_detail = CatchAllDetail(
            detected=catch_all_value is True,
            probability=catch_all_probability,
            confidence=confidence,
            legitimate_use_likely=legitimate_use_likely,
            type=ca_type,
        )

    summary = scorer.build_summary(
        breakdown.fired, breakdown.trust_fired,
        breakdown.final_clamped, rec,
        domain_age_days=dns_result.domain_age_days,
        catch_all=catch_all_value,
    )

    # `disposable` is only true when a blocklist signal fired. Deliverability
    # problems (no MX, NXDOMAIN) and syntax errors handled in the hard
    # disqualifier path — they reach this point only if they didn't fire.
    disposable = _is_disposable(all_signal_names)
    valid_address = _is_valid_address(syntax_ok=True, has_mx=dns_result.has_mx)
    catch_all_checked_flag = ca_result is not None and ca_result.checked

    response = CheckResponse(
        meta=Meta(
            request_id=request_id, email=email, domain=domain,
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - t_start) * 1000),
            model_phase=phase, model_version=settings.model_version,
            path_taken=path_taken, cached=False,
        ),
        verdict=Verdict(
            recommendation=rec, risk_level=rlvl,
            disposable=disposable, catch_all=catch_all_value,
            catch_all_checked=catch_all_checked_flag,
            valid_address=valid_address,
            safe_to_send=(rec == scorer.Recommendation.ALLOW),
            summary=summary,
        ),
        score=Score(
            value=breakdown.final_clamped, confidence=round(confidence, 2),
            confidence_level=conf_level,
            components=ScoreComponents(
                strong_signals=breakdown.strong_total,
                corroborating=breakdown.corroborating_compounded,
                trust_adjustments=breakdown.trust_adjustments,
                compounding_bonus=breakdown.compounding_bonus,
                final_clamped=breakdown.final_clamped,
            ),
            thresholds=Thresholds(
                block_at=thresholds.block, flag_at=thresholds.flag,
                your_profile=profile,
            ),
            catch_all_detail=catch_all_detail,
        ),
        signals=Signals(
            fired=fired_objs, trust_signals=trust_objs,
            compounding=Compounding(
                applied=corroborating_count > 1,
                signal_count=corroborating_count,
                bonus_applied=breakdown.compounding_bonus,
                explanation=(
                    f"{corroborating_count} independent corroborating signals compound non-linearly."
                    if corroborating_count > 1 else ""
                ),
            ),
        ),
        checks=Checks(
            run=[Check(**c) for c in check_records],
            path_explanation=_path_explanation(path_taken, bool(bl_result.hit), catch_all_value is not None),
        ),
    )

    # ── Record behavioral history + cache ───────────────────────────────────
    if api_key_id:
        asyncio.ensure_future(behavioral.record_query(domain, api_key_id, redis))

    has_new_domain = any(
        s in all_signal_names
        for s in ("new_domain_30d", "new_domain_90d", "domain_age_under_7_days", "catch_all_new_domain")
    )
    fraud_confirmed = breakdown.final_clamped >= 90 and confidence >= 0.8
    trusted = "known_legitimate_provider" in all_signal_names or "known_disposable_domain_high_confidence" in all_signal_names
    await _cache_response(redis, cache_key, response, has_new_domain, fraud_confirmed, trusted)

    _record_async(api_key_id, response)
    return response


def _path_explanation(path: str, blocklist_hit: bool, catch_all_ran: bool) -> str:
    if path == "fast" and blocklist_hit:
        return "Blocklist hit on fast path — no DNS or SMTP checks needed."
    if path == "deep":
        return (
            "Fast path inconclusive; standard path ran parallel DNS/behavioral checks; "
            "synchronous deep path ran SMTP catch-all probe."
        )
    return "Fast path inconclusive; standard path ran parallel DNS/behavioral checks."


# ── Cache serialisation ──────────────────────────────────────────────────────

async def _cache_response(
    redis: RedisClient, key: str, response: CheckResponse,
    has_new_domain: bool, fraud: bool, trusted: bool,
) -> None:
    """
    Cache the domain-level verdict. Strip per-request PII (email + request_id)
    before writing — the rehydrate path fills them in from the current request,
    so the stored blob never retains another user's email address.
    """
    ttl = _pick_cache_ttl(response.score.value, has_new_domain, fraud, trusted)
    try:
        sanitised = response.model_copy(deep=True)
        sanitised.meta.email = ""
        sanitised.meta.request_id = ""
        await redis.setex(key, ttl, sanitised.model_dump_json())
    except Exception as exc:
        logger.debug("Cache write failed for %s: %s", key, exc)


def _rehydrate_cached_response(
    data: dict, email: str, domain: str, request_id: str, t_start: float,
    phase: ModelPhase, profile: RiskProfile, thresholds, settings,
) -> CheckResponse:
    """
    Replay cached body with per-request overrides: new request_id, latency, cached=True.
    The stored thresholds are overridden with the current request's profile so a
    customer who changes profile sees their profile reflected.
    """
    response = CheckResponse.model_validate(data)

    # Per-request overrides
    response.meta.request_id = request_id
    response.meta.email = email
    response.meta.domain = domain
    response.meta.latency_ms = int((time.monotonic() - t_start) * 1000)
    response.meta.cached = True
    response.meta.path_taken = "cached"
    response.meta.cache_age_seconds = None  # TTL inspection would need a TTL call; skip for now

    # Re-resolve thresholds under current profile
    response.score.thresholds = Thresholds(
        block_at=thresholds.block, flag_at=thresholds.flag, your_profile=profile,
    )

    # Re-derive recommendation under current profile/confidence
    fired_names = [s.name for s in response.signals.fired] + [s.name for s in response.signals.trust_signals]
    response.verdict.recommendation = scorer.derive_recommendation(
        response.score.value, response.score.confidence, fired_names, thresholds,
    )

    return response
