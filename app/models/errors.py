"""
Error responses — unified envelope per blueprint §15.

Every error includes `code` (machine-readable), `http_status`, `message`,
`request_id`, and `docs_url`. No raw FastAPI `detail[]` arrays leak through;
the custom exception handler in app/main.py rewrites them.
"""

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Self-documenting error — developer should never need to Google anything."""

    code: str = Field(description="Machine-readable identifier e.g. 'rate_limit_exceeded'")
    http_status: int
    message: str
    request_id: str = Field("", description="Copy this into support tickets")
    docs_url: str = ""

    # Rate-limit specific (nullable elsewhere)
    reset_at: str | None = None
    used: int | None = None
    limit: int | None = None
    upgrade_url: str | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


DOCS_BASE = "https://docs.disposablecheck.com"


def rate_limit_error(used: int, limit: int, reset_at: str) -> ErrorDetail:
    return ErrorDetail(
        code="rate_limit_exceeded",
        http_status=429,
        message=f"You have used {used} of your {limit} checks this month.",
        reset_at=reset_at,
        used=used,
        limit=limit,
        upgrade_url="https://disposablecheck.com/pricing",
        docs_url=f"{DOCS_BASE}/rate-limits",
    )


def invalid_key_error() -> ErrorDetail:
    return ErrorDetail(
        code="invalid_api_key",
        http_status=401,
        message="API key is missing or invalid. Get a free key at disposablecheck.com",
        docs_url=f"{DOCS_BASE}/authentication",
    )


def invalid_email_param_error() -> ErrorDetail:
    return ErrorDetail(
        code="invalid_request",
        http_status=422,
        message="'email' query parameter is required. Example: GET /v1/check?email=user@example.com",
        docs_url=f"{DOCS_BASE}/check",
    )


def validation_error(message: str) -> ErrorDetail:
    return ErrorDetail(
        code="validation_error",
        http_status=422,
        message=message,
        docs_url=f"{DOCS_BASE}/errors",
    )


def invalid_session_error() -> ErrorDetail:
    return ErrorDetail(
        code="invalid_session",
        http_status=401,
        message="You are not signed in. Log in to access this resource.",
        docs_url=f"{DOCS_BASE}/authentication",
    )


def invalid_magic_link_error() -> ErrorDetail:
    return ErrorDetail(
        code="invalid_magic_link",
        http_status=400,
        message="This link is invalid, expired, or has already been used. Request a new one.",
        docs_url=f"{DOCS_BASE}/authentication",
    )


def quota_exceeded_error() -> ErrorDetail:
    return ErrorDetail(
        code="quota_exceeded",
        http_status=402,
        message="You are out of checks. Buy a bundle to keep going.",
        upgrade_url="https://email-api-landing.vercel.app/dashboard/billing",
        docs_url=f"{DOCS_BASE}/billing",
    )


def email_send_failed_error() -> ErrorDetail:
    return ErrorDetail(
        code="email_send_failed",
        http_status=502,
        message="We could not send the verification email. Please try again in a moment.",
        docs_url=f"{DOCS_BASE}/authentication",
    )


def internal_error() -> ErrorDetail:
    return ErrorDetail(
        code="internal_error",
        http_status=500,
        message="An unexpected error occurred. This has been logged. Try again in a few seconds.",
        docs_url=f"{DOCS_BASE}/errors",
    )


# ── Backwards-compatible class alias ──────────────────────────────────────────
# Code written against the old `ErrorResponse` shape still works — it now
# extends ErrorDetail so every error automatically carries `request_id`
# and `http_status`.
ErrorResponse = ErrorDetail
