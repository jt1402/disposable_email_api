"""
Layer 5 — Catch-All Detection (~500ms)

SMTP RCPT TO probing with a UUID address. 250 → catch-all. 550 → not catch-all.
Never sends actual email — probes the SMTP handshake only.

Note: this is the single-probe MVP. The staged warm/cold probe + Bayesian
confidence accumulation (§2 of the scoring engine technical reference) is
Month-2 work — see Tier C of the upgrade plan.

Only runs when CATCHALL_ENABLED=true AND caller is Pro/Enterprise tier.

The engine promotes `catch_all_domain` to the named compound
`catch_all_new_domain` (weight 85) when combined with a new-domain signal.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_CACHE_TTL_CONFIRMED = 86_400 * 3   # catch-all config is stable — 3 days
_CACHE_TTL_CLEARED = 86_400          # re-verify cleared results daily
_SMTP_PORT = 25


@dataclass
class CheckRecord:
    name: str
    status: str
    duration_ms: float
    result: str | None = None
    probe_detail: dict | None = None


@dataclass
class CatchAllResult:
    checked: bool = False
    is_catch_all: bool | None = None
    probability: float = 0.0
    signals: list[str] = field(default_factory=list)
    confidence_penalties: list[str] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)


async def _probe_smtp(mx_host: str, domain: str, timeout: float) -> tuple[bool | None, float, str]:
    """
    Returns (is_catch_all, duration_ms, response_code).
    is_catch_all: True if RCPT TO accepted UUID address, False if rejected, None on failure.
    """
    probe_address = f"{uuid.uuid4().hex}@{domain}"
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, _SMTP_PORT),
            timeout=timeout,
        )
        try:
            await asyncio.wait_for(reader.readline(), timeout=timeout)

            async def send(cmd: str) -> str:
                writer.write((cmd + "\r\n").encode())
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                return line.decode(errors="replace").strip()

            ehlo_resp = await send("EHLO verifymailapi.com")
            if not ehlo_resp.startswith(("250", "220")):
                return None, (time.monotonic() - start) * 1000, ehlo_resp[:3]

            mail_resp = await send("MAIL FROM:<probe@verifymailapi.com>")
            if not mail_resp.startswith("250"):
                return None, (time.monotonic() - start) * 1000, mail_resp[:3]

            rcpt_resp = await send(f"RCPT TO:<{probe_address}>")
            elapsed_ms = (time.monotonic() - start) * 1000
            code = rcpt_resp[:3]

            if rcpt_resp.startswith(("250", "251")):
                return True, elapsed_ms, code
            if rcpt_resp.startswith(("550", "551", "553")):
                return False, elapsed_ms, code
            return None, elapsed_ms, code

        finally:
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()

    except (TimeoutError, ConnectionRefusedError, OSError) as exc:
        logger.debug("SMTP probe failed for %s via %s: %s", domain, mx_host, exc)
        return None, (time.monotonic() - start) * 1000, "error"


async def check(
    domain: str,
    mx_hosts: list[str],
    redis: RedisClient,
    timeout: float = 5.0,
) -> CatchAllResult:
    if not mx_hosts:
        return CatchAllResult(checked=False)

    cache_key = f"catchall:{domain}"
    cached = await redis.get(cache_key)
    if cached is not None:
        is_catch_all = cached == "1"
        return CatchAllResult(
            checked=True,
            is_catch_all=is_catch_all,
            probability=0.85 if is_catch_all else 0.05,
            signals=["catch_all_domain"] if is_catch_all else [],
        )

    result_bool, duration_ms, code = await _probe_smtp(mx_hosts[0], domain, timeout)

    probe_detail = {"response_code": code, "probe_type": "cold_uuid"}
    checks = [CheckRecord(
        name="smtp_catch_all_probe",
        status="completed" if result_bool is not None else "failed",
        duration_ms=duration_ms,
        result="catch_all_confirmed" if result_bool else ("not_catch_all" if result_bool is False else "inconclusive"),
        probe_detail=probe_detail,
    )]

    if result_bool is None:
        return CatchAllResult(
            checked=True,
            is_catch_all=None,
            confidence_penalties=["smtp_probe_timeout"],
            checks=checks,
        )

    ttl = _CACHE_TTL_CONFIRMED if result_bool else _CACHE_TTL_CLEARED
    await redis.setex(cache_key, ttl, "1" if result_bool else "0")

    return CatchAllResult(
        checked=True,
        is_catch_all=result_bool,
        probability=0.85 if result_bool else 0.05,
        signals=["catch_all_domain"] if result_bool else [],
        checks=checks,
    )
