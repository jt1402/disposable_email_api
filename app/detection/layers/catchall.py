"""
Layer 5 — Catch-All Detection (~500ms)

SMTP RCPT TO probing. Only runs when:
  - CATCHALL_ENABLED=true in env
  - The caller's tier is Pro or Enterprise

A catch-all domain accepts email for ANY address (including random UUIDs).
This bypasses every list-based check — the most common advanced disposable attack.

Detection: connect to the domain's MX server, send EHLO + MAIL FROM + RCPT TO with
a random UUID local part. 250 → catch-all. 550 → not catch-all.
Never sends actual email — probes the SMTP handshake only.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field

from app.services.redis_client import RedisClient

logger = logging.getLogger(__name__)

_CACHE_TTL = 86_400  # 24 hours per domain
_SMTP_PORT = 25


@dataclass
class CatchAllResult:
    checked: bool = False
    is_catch_all: bool | None = None
    signals: list[str] = field(default_factory=list)


async def _probe_smtp(mx_host: str, domain: str, timeout: float) -> bool | None:
    """
    Returns True if catch-all, False if not, None if probe failed/inconclusive.
    Never sends actual mail — exits after RCPT TO response.
    """
    probe_address = f"{uuid.uuid4().hex}@{domain}"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, _SMTP_PORT),
            timeout=timeout,
        )
        try:
            # Read banner
            await asyncio.wait_for(reader.readline(), timeout=timeout)

            async def send(cmd: str) -> str:
                writer.write((cmd + "\r\n").encode())
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                return line.decode(errors="replace").strip()

            ehlo_resp = await send("EHLO disposablecheck.com")
            if not ehlo_resp.startswith(("250", "220")):
                return None

            mail_resp = await send("MAIL FROM:<probe@disposablecheck.com>")
            if not mail_resp.startswith("250"):
                return None

            rcpt_resp = await send(f"RCPT TO:<{probe_address}>")

            # 250/251 → accepted → catch-all
            if rcpt_resp.startswith(("250", "251")):
                return True
            # 550/551/553 → rejected → not catch-all
            elif rcpt_resp.startswith(("550", "551", "553")):
                return False
            else:
                return None  # 421, 450, 452, etc. — inconclusive

        finally:
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        logger.debug("SMTP probe failed for %s via %s: %s", domain, mx_host, exc)
        return None


async def check(
    domain: str,
    mx_hosts: list[str],
    redis: RedisClient,
    timeout: float = 5.0,
) -> CatchAllResult:
    if not mx_hosts:
        return CatchAllResult(checked=False)

    # ── Cache check ──────────────────────────────────────────────────────────
    cache_key = f"catchall:{domain}"
    cached = await redis.get(cache_key)
    if cached is not None:
        is_catch_all = cached == "1"
        return CatchAllResult(
            checked=True,
            is_catch_all=is_catch_all,
            signals=["catch_all_domain"] if is_catch_all else [],
        )

    # ── Probe primary MX only ────────────────────────────────────────────────
    # Using first (lowest priority) MX. Rate limit: once per domain per 24h enforced by cache.
    result_bool = await _probe_smtp(mx_hosts[0], domain, timeout)

    if result_bool is None:
        # Probe inconclusive — don't cache, don't penalise
        return CatchAllResult(checked=True, is_catch_all=None)

    await redis.setex(cache_key, _CACHE_TTL, "1" if result_bool else "0")

    return CatchAllResult(
        checked=True,
        is_catch_all=result_bool,
        signals=["catch_all_domain"] if result_bool else [],
    )
