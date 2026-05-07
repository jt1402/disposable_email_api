"""
Outbound webhook dispatcher for async check completion.

Used by `/v1/check/async`: once the deep SMTP / catch-all path finishes,
we POST the final CheckResponse to the customer's webhook URL.

Guards:
  - https:// only — http endpoints are rejected up front
  - SSRF protection — refuse to POST to private / loopback / link-local IPs
  - Retry policy — 3 attempts with exponential backoff (1s, 5s, 25s)
  - HMAC signature header when the customer supplies a secret
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_RETRY_DELAYS = (1.0, 5.0, 25.0)
_REQUEST_TIMEOUT = 10.0
_USER_AGENT = "VerifyMail-Webhook/1.0"


def is_safe_webhook_url(url: str) -> tuple[bool, str]:
    """
    Block non-HTTPS, missing host, and private/internal addresses.
    Returns (ok, reason). reason is empty on success.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid_url"
    if parsed.scheme != "https":
        return False, "scheme_must_be_https"
    if not parsed.hostname:
        return False, "missing_host"

    host = parsed.hostname
    try:
        # Resolve all A/AAAA addresses; if *any* is private we refuse —
        # blocks DNS-rebinding tricks where 127.0.0.1 hides behind a public name.
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "dns_lookup_failed"
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, "private_ip_not_allowed"
    return True, ""


def _sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def deliver(
    url: str,
    payload: dict,
    *,
    secret: str | None = None,
    request_id: str = "",
) -> bool:
    """
    POST `payload` to `url`, returning True on 2xx, False after exhausting retries.
    Never raises — webhook failures must not crash the worker task.
    """
    ok, reason = is_safe_webhook_url(url)
    if not ok:
        logger.warning("Refusing webhook delivery to %s: %s (request_id=%s)", url, reason, request_id)
        return False

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
        "X-VerifyMail-Request-Id": request_id,
        "X-VerifyMail-Event": payload.get("event", "check.completed"),
    }
    if secret:
        headers["X-VerifyMail-Signature"] = _sign(secret, body)

    last_status: int | None = None
    last_exc: Exception | None = None

    for attempt, delay in enumerate(_RETRY_DELAYS, start=1):
        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                resp = await client.post(url, content=body, headers=headers)
            last_status = resp.status_code
            if 200 <= resp.status_code < 300:
                return True
            # 4xx (except 408/429) are not retryable — customer config issue.
            if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
                logger.warning(
                    "Webhook %s returned %d (non-retryable). request_id=%s",
                    url, resp.status_code, request_id,
                )
                return False
        except httpx.HTTPError as exc:
            last_exc = exc

        if attempt < len(_RETRY_DELAYS):
            await asyncio.sleep(delay)

    logger.warning(
        "Webhook delivery exhausted for %s (status=%s, exc=%s, request_id=%s)",
        url, last_status, last_exc, request_id,
    )
    return False
