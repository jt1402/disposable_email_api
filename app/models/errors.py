from typing import Optional

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Self-documenting error — developer should never need to Google anything."""

    error: str
    code: int
    message: str
    reset_at: Optional[str] = None
    upgrade_url: Optional[str] = None
    docs_url: Optional[str] = None


DOCS_BASE = "https://docs.disposablecheck.com"


def rate_limit_error(used: int, limit: int, reset_at: str) -> ErrorResponse:
    return ErrorResponse(
        error="rate_limit_exceeded",
        code=429,
        message=f"You've used {used}/{limit} checks this month",
        reset_at=reset_at,
        upgrade_url="https://disposablecheck.com/pricing",
        docs_url=f"{DOCS_BASE}/rate-limits",
    )


def invalid_key_error() -> ErrorResponse:
    return ErrorResponse(
        error="invalid_api_key",
        code=401,
        message="API key is missing or invalid. Get a free key at disposablecheck.com",
        docs_url=f"{DOCS_BASE}/authentication",
    )


def invalid_email_param_error() -> ErrorResponse:
    return ErrorResponse(
        error="invalid_request",
        code=422,
        message="'email' query parameter is required. Example: GET /v1/check?email=user@example.com",
        docs_url=f"{DOCS_BASE}/check",
    )


def internal_error() -> ErrorResponse:
    return ErrorResponse(
        error="internal_error",
        code=500,
        message="An unexpected error occurred. This has been logged. Try again in a few seconds.",
        docs_url=f"{DOCS_BASE}/errors",
    )
