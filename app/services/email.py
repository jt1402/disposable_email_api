"""
Transactional email via Resend.

Using the REST API directly (not an SDK) for consistency with the Unkey
integration and to keep the dep surface small.
Docs: https://resend.com/docs/api-reference
"""

import logging
from dataclasses import dataclass

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

RESEND_BASE = "https://api.resend.com"


@dataclass
class SendResult:
    ok: bool
    message_id: str = ""
    error: str = ""


async def send_email(to: str, subject: str, html: str, text: str) -> SendResult:
    settings = get_settings()
    if not settings.resend_api_key:
        # Dev mode: log the email contents instead of sending.
        logger.warning("RESEND_API_KEY not set — printing email to logs instead")
        logger.info("[DEV EMAIL] to=%s subject=%s\n%s", to, subject, text)
        return SendResult(ok=True, message_id="dev")

    payload = {
        "from": settings.resend_from_email,
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{RESEND_BASE}/emails",
                headers={"Authorization": f"Bearer {settings.resend_api_key}"},
                json=payload,
            )
        if resp.status_code >= 400:
            logger.error("Resend returned %s: %s", resp.status_code, resp.text)
            return SendResult(ok=False, error=f"resend_http_{resp.status_code}")
        data = resp.json()
    except httpx.RequestError as exc:
        logger.error("Resend request failed: %s", exc)
        return SendResult(ok=False, error="email_service_unavailable")

    return SendResult(ok=True, message_id=data.get("id", ""))


def _magic_link_body(verify_url: str, purpose: str) -> tuple[str, str, str]:
    """Return (subject, html, text) for a magic-link email."""
    if purpose == "signup_verify":
        subject = "Verify your VerifyMail email"
        heading = "Welcome to VerifyMail"
        intro = "Click the link below to verify your email and activate your free API key."
    else:
        subject = "Sign in to VerifyMail"
        heading = "Sign in to VerifyMail"
        intro = "Click the link below to sign in. It expires in 15 minutes."

    text = (
        f"{heading}\n\n"
        f"{intro}\n\n"
        f"{verify_url}\n\n"
        "If you did not request this email, you can safely ignore it."
    )

    html = f"""<!doctype html>
<html>
  <body style="font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif;
               background:#fafaf9;margin:0;padding:32px;color:#0a0a0f;">
    <table role="presentation" cellpadding="0" cellspacing="0"
           style="max-width:480px;margin:0 auto;background:#fff;
                  border:1px solid #e8e8e5;border-radius:12px;padding:32px;">
      <tr><td>
        <h1 style="font-size:20px;margin:0 0 12px;letter-spacing:-0.02em;">
          {heading}
        </h1>
        <p style="font-size:15px;color:#525866;line-height:1.55;margin:0 0 24px;">
          {intro}
        </p>
        <a href="{verify_url}"
           style="display:inline-block;background:#2E6F9E;color:#fff;
                  text-decoration:none;padding:12px 20px;border-radius:8px;
                  font-size:14px;font-weight:500;">
          Continue →
        </a>
        <p style="font-size:13px;color:#9ca3af;line-height:1.55;margin:24px 0 0;">
          Or paste this link into your browser:<br>
          <span style="word-break:break-all;">{verify_url}</span>
        </p>
        <p style="font-size:13px;color:#9ca3af;margin:24px 0 0;">
          If you did not request this email, you can safely ignore it.
        </p>
      </td></tr>
    </table>
  </body>
</html>"""

    return subject, html, text


async def send_magic_link(to: str, verify_url: str, purpose: str) -> SendResult:
    subject, html, text = _magic_link_body(verify_url, purpose)
    return await send_email(to, subject, html, text)
