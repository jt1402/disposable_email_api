"""
Layer 3 — DNS Intelligence (~50–200ms parallel)

MX analysis, domain age via WHOIS, SPF/DKIM/DMARC lookups, MX cluster check,
legitimate-MX detection (Google Workspace, Microsoft 365, etc.).

Emits both risk signals and trust signals (domain_age_over_5_years,
spf_dkim_dmarc_all_present, mx_known_legitimate_host) — critical for keeping
false-positive rate low on established B2B domains that use catch-all.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC

import aiodns

from app.core.config import get_settings
from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_CACHE_TTL_DNS = 86_400
_CACHE_TTL_WHOIS = 604_800

# Single shared resolver with tries=1 — aiodns defaults to 4 retries per query,
# which multiplies timeouts on slow / missing records. One try is enough for
# optional records like SPF / DMARC / DKIM.
_resolver: aiodns.DNSResolver | None = None


def _get_resolver() -> aiodns.DNSResolver:
    global _resolver
    if _resolver is None:
        settings = get_settings()
        nameservers = [
            s.strip() for s in settings.dns_nameservers.split(",") if s.strip()
        ] or None
        # tries=1: single attempt. timeout: per-attempt hard ceiling.
        _resolver = aiodns.DNSResolver(
            timeout=settings.dns_timeout,
            tries=1,
            nameservers=nameservers,
        )
    return _resolver

REDIS_DNS_CACHE_KEY = "dns_cache:{}"
REDIS_WHOIS_CACHE_KEY = "whois_age:{}"


# Substring patterns on the MX host — if a domain's MX contains one, it is
# almost certainly a major legitimate mail provider.
_LEGITIMATE_MX_PATTERNS: tuple[str, ...] = (
    # Google — both consumer (gmail.com) and Workspace (custom domains)
    "aspmx.l.google.com",
    "gmail-smtp-in.l.google.com",
    "googlemail.com",
    # Microsoft — Outlook.com consumer + Microsoft 365
    ".mail.protection.outlook.com",
    ".olc.protection.outlook.com",
    "hotmail.com",
    # Apple iCloud
    ".mail.icloud.com",
    "mx1.mail.icloud.com",
    # Yahoo
    ".yahoodns.net",
    "mta5.am0.yahoodns.net",
    # Zoho
    "mx.zoho.com",
    "zohomail.com",
    # Fastmail / Messagingengine
    "aspmx.fastmail.com",
    "messagingengine.com",
    # Proton
    "mail.protonmail.ch",
    "mailsec.protonmail.ch",
    # Others
    "mailbox.org",
    "mx.yandex.net",
    "mxbiz1.qq.com",
    "hostedemail.com",        # Rackspace
    "emailsrvr.com",          # Rackspace
    "pphosted.com",           # Proofpoint
    "mimecast.com",
)


@dataclass
class CheckRecord:
    name: str
    status: str
    duration_ms: float
    result: str | None = None
    probe_detail: dict | None = None


@dataclass
class DnsResult:
    has_mx: bool = False
    mx_hosts: list[str] = field(default_factory=list)
    mx_shared_with_disposables: bool = False
    mx_known_legitimate: bool = False
    domain_age_days: int | None = None
    has_spf: bool | None = None
    has_dkim: bool | None = None
    has_dmarc: bool | None = None
    signals: list[str] = field(default_factory=list)
    confidence_penalties: list[str] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)


# ── Low-level lookups ─────────────────────────────────────────────────────────

async def _resolve_mx(domain: str, timeout: float) -> list[str] | None:
    """Returns None on lookup failure, [] on legitimate NXDOMAIN."""
    try:
        records = await asyncio.wait_for(
            _get_resolver().query(domain, "MX"), timeout=timeout,
        )
        return [r.host.rstrip(".").lower() for r in sorted(records, key=lambda x: x.priority)]
    except TimeoutError:
        logger.debug("MX lookup timed out for %s", domain)
        return None
    except aiodns.error.DNSError as exc:
        if getattr(exc, "args", [None])[0] == 4:  # ENOTFOUND
            return []
        return None
    except Exception as exc:
        logger.debug("MX lookup failed for %s: %s", domain, exc)
        return None


async def _resolve_txt(domain: str, timeout: float) -> list[str] | None:
    try:
        records = await asyncio.wait_for(
            _get_resolver().query(domain, "TXT"), timeout=timeout,
        )
        out: list[str] = []
        for r in records:
            text = getattr(r, "text", "")
            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="replace")
            out.append(text)
        return out
    except TimeoutError:
        return None
    except aiodns.error.DNSError as exc:
        if getattr(exc, "args", [None])[0] == 4:
            return []
        return None
    except Exception as exc:
        logger.debug("TXT lookup failed for %s: %s", domain, exc)
        return None


async def _check_spf(domain: str, timeout: float) -> bool | None:
    txt = await _resolve_txt(domain, timeout)
    if txt is None:
        return None
    return any(t.lower().startswith("v=spf1") for t in txt)


async def _check_dmarc(domain: str, timeout: float) -> bool | None:
    txt = await _resolve_txt(f"_dmarc.{domain}", timeout)
    if txt is None:
        return None
    return any(t.lower().startswith("v=dmarc1") for t in txt)


async def _check_dkim_common_selectors(domain: str, timeout: float) -> bool | None:
    """
    DKIM selectors are domain-specific and not discoverable — you cannot
    enumerate them. We fire a handful of common selectors in parallel and
    return True if any respond. Absent = not conclusive (could be a custom
    selector), so we return None rather than False.

    Fast-path: runs all selector probes concurrently, short TTL.
    """
    # Short per-probe timeout — any single selector that doesn't answer
    # quickly is treated as a miss. Total worst-case ~1s (parallel).
    probe_timeout = min(timeout, 1.0)
    selectors = ("google", "default", "selector1", "s1", "k1")
    tasks = [
        _resolve_txt(f"{sel}._domainkey.{domain}", probe_timeout)
        for sel in selectors
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for txt in results:
        if isinstance(txt, list) and txt and any(
            "v=dkim1" in t.lower() or "k=rsa" in t.lower() for t in txt
        ):
            return True
    return None  # Inconclusive — absence does not prove no DKIM


async def _get_domain_age_days(domain: str, timeout: float) -> int | None:
    from datetime import datetime
    try:
        import whois  # type: ignore[import-untyped]
        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=timeout)
        creation = w.creation_date
        if creation is None:
            return None
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime):
            return None
        now = datetime.now(UTC).replace(tzinfo=None)
        naive_creation = creation.replace(tzinfo=None) if creation.tzinfo else creation
        return max(0, (now - naive_creation).days)
    except TimeoutError:
        return None
    except Exception as exc:
        logger.debug("WHOIS failed for %s: %s", domain, exc)
        return None


def _is_legitimate_mx(mx_host: str) -> bool:
    host = mx_host.lower()
    return any(pattern in host for pattern in _LEGITIMATE_MX_PATTERNS)


# ── Main entry ───────────────────────────────────────────────────────────────

async def check(domain: str, redis: RedisClient) -> DnsResult:
    settings = get_settings()

    # ── Full DNS result cache ────────────────────────────────────────────────
    cache_key = REDIS_DNS_CACHE_KEY.format(domain)
    cached = await redis.get(cache_key)
    if cached:
        try:
            data = json.loads(cached)
            # Rehydrate check records
            checks = [CheckRecord(**c) for c in data.pop("checks", [])]
            return DnsResult(checks=checks, **data)
        except (TypeError, ValueError) as exc:
            logger.debug("Stale DNS cache for %s: %s", domain, exc)

    signals: list[str] = []
    penalties: list[str] = []
    checks: list[CheckRecord] = []

    # ── Run MX + SPF + DMARC + DKIM in parallel, with hard per-task caps ─────
    async def timed(coro, name: str) -> tuple[object, float, str]:
        t = time.monotonic()
        status = "completed"
        try:
            result = await coro
        except Exception as exc:
            logger.debug("%s raised: %s", name, exc)
            result = None
            status = "failed"
        return result, (time.monotonic() - t) * 1000, status

    mx_res, spf_res, dmarc_res, dkim_res = await asyncio.gather(
        timed(_resolve_mx(domain, settings.dns_timeout), "mx"),
        timed(_check_spf(domain, settings.dns_timeout), "spf"),
        timed(_check_dmarc(domain, settings.dns_timeout), "dmarc"),
        timed(_check_dkim_common_selectors(domain, settings.dns_timeout), "dkim"),
    )
    mx_hosts, mx_ms, mx_status = mx_res
    has_spf, spf_ms, spf_status = spf_res
    has_dmarc, dmarc_ms, dmarc_status = dmarc_res
    has_dkim, dkim_ms, _ = dkim_res

    checks.append(CheckRecord(
        name="mx_record_lookup",
        status="completed" if mx_hosts is not None else "failed",
        duration_ms=mx_ms,
        result=(
            f"{len(mx_hosts)} record(s): {', '.join(mx_hosts[:3])}"
            + (f" (+{len(mx_hosts) - 3} more)" if len(mx_hosts) > 3 else "")
            if mx_hosts else ("no_mx_records" if mx_hosts == [] else None)
        ),
    ))

    # ── No MX at all → hard disqualifier ─────────────────────────────────────
    if mx_hosts is not None and len(mx_hosts) == 0:
        signals.append("no_mx_records")
        result = DnsResult(
            has_mx=False, signals=signals, confidence_penalties=penalties, checks=checks,
        )
        await _cache_result(redis, cache_key, result)
        return result

    # ── MX lookup failed entirely → record penalty but continue ─────────────
    if mx_hosts is None:
        penalties.append("mx_lookup_timeout")
        mx_hosts = []

    mx_known_legitimate = any(_is_legitimate_mx(mx) for mx in mx_hosts)
    if mx_known_legitimate:
        signals.append("mx_known_legitimate_host")

    # ── MX cluster fingerprint check (shared with known-disposables) ────────
    mx_shared = False
    if mx_hosts:
        from app.detection.layers.blocklist import get_mx_cluster_count
        cluster_checks = await asyncio.gather(
            *[get_mx_cluster_count(mx, redis) for mx in mx_hosts],
            return_exceptions=True,
        )
        for count in cluster_checks:
            if isinstance(count, int) and count >= settings.mx_cluster_threshold:
                mx_shared = True
                signals.append("suspicious_mx_infrastructure")
                break

    # ── SPF / DKIM / DMARC ───────────────────────────────────────────────────
    checks.append(CheckRecord(
        name="spf_lookup",
        status="completed" if has_spf is not None else "failed",
        duration_ms=spf_ms,
        result=("present" if has_spf else "absent") if has_spf is not None else None,
    ))
    checks.append(CheckRecord(
        name="dmarc_lookup",
        status="completed" if has_dmarc is not None else "failed",
        duration_ms=dmarc_ms,
        result=("present" if has_dmarc else "absent") if has_dmarc is not None else None,
    ))
    checks.append(CheckRecord(
        name="dkim_lookup",
        status="completed",
        duration_ms=dkim_ms,
        result="present" if has_dkim is True else "selector_not_found",
    ))

    # Treat "lookup failed" and "definitely absent" as equivalent for scoring:
    # a legitimate domain almost always resolves cleanly. We still record a
    # confidence penalty when the lookup failed so the recommendation layer
    # knows the signal was softer.
    if has_spf is None:
        penalties.append("spf_lookup_failed")
        signals.append("no_spf_record")
    elif not has_spf:
        signals.append("no_spf_record")

    if has_dmarc is None:
        penalties.append("dmarc_lookup_failed")
        signals.append("no_dmarc_record")
    elif not has_dmarc:
        signals.append("no_dmarc_record")

    # Trust signal: full email authentication stack present.
    # DKIM selectors are domain-specific — we only probe common ones, so we
    # accept "MX legitimate + SPF + DMARC" as equivalent evidence even when
    # our DKIM probe missed the custom selector.
    has_full_auth = has_spf is True and has_dmarc is True and (has_dkim is True or mx_known_legitimate)
    if has_full_auth:
        signals.append("spf_dkim_dmarc_all_present")

    # ── Domain age via WHOIS ─────────────────────────────────────────────────
    t_whois = time.monotonic()
    age_cache_key = REDIS_WHOIS_CACHE_KEY.format(domain)
    age_cached = await redis.get(age_cache_key)

    if age_cached is not None:
        try:
            domain_age_days: int | None = int(age_cached) if age_cached != "null" else None
        except ValueError:
            domain_age_days = None
    else:
        domain_age_days = await _get_domain_age_days(domain, settings.whois_timeout)
        await redis.setex(
            age_cache_key, _CACHE_TTL_WHOIS,
            str(domain_age_days) if domain_age_days is not None else "null",
        )

    checks.append(CheckRecord(
        name="domain_age_lookup",
        status="completed" if domain_age_days is not None else "failed",
        duration_ms=(time.monotonic() - t_whois) * 1000,
        result=f"{domain_age_days} days" if domain_age_days is not None else None,
    ))

    # ── Age signals (risk or trust) ──────────────────────────────────────────
    if domain_age_days is None:
        signals.append("domain_age_unknown")
        penalties.append("whois_lookup_failed")
    elif domain_age_days < 7:
        signals.append("domain_age_under_7_days")
    elif domain_age_days < 30:
        signals.append("new_domain_30d")
    elif domain_age_days < 90:
        signals.append("new_domain_90d")
    elif domain_age_days >= 5 * 365:
        signals.append("domain_age_over_5_years")
    elif domain_age_days >= 2 * 365:
        signals.append("domain_age_over_2_years")

    result = DnsResult(
        has_mx=bool(mx_hosts),
        mx_hosts=mx_hosts,
        mx_shared_with_disposables=mx_shared,
        mx_known_legitimate=mx_known_legitimate,
        domain_age_days=domain_age_days,
        has_spf=has_spf,
        has_dkim=has_dkim,
        has_dmarc=has_dmarc,
        signals=signals,
        confidence_penalties=penalties,
        checks=checks,
    )
    await _cache_result(redis, cache_key, result)
    return result


async def _cache_result(redis: RedisClient, key: str, result: DnsResult) -> None:
    payload = {
        "has_mx": result.has_mx,
        "mx_hosts": result.mx_hosts,
        "mx_shared_with_disposables": result.mx_shared_with_disposables,
        "mx_known_legitimate": result.mx_known_legitimate,
        "domain_age_days": result.domain_age_days,
        "has_spf": result.has_spf,
        "has_dkim": result.has_dkim,
        "has_dmarc": result.has_dmarc,
        "signals": result.signals,
        "confidence_penalties": result.confidence_penalties,
        "checks": [
            {
                "name": c.name, "status": c.status, "duration_ms": c.duration_ms,
                "result": c.result, "probe_detail": c.probe_detail,
            }
            for c in result.checks
        ],
    }
    await redis.setex(key, _CACHE_TTL_DNS, json.dumps(payload))
