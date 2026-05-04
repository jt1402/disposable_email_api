"""
FastAPI application entry point.

Startup: initialise Redis + PostgreSQL connections.
Shutdown: gracefully close connections.
"""

import logging
import secrets
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.routes import auth, billing, check, health, keys, oauth, report, usage, webhooks
from app.core.config import get_settings
from app.models.errors import ErrorDetail, internal_error, validation_error
from app.services import db as database
from app.services.redis_client import close_redis, init_redis

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()

    logger.info("Starting up — connecting to Redis and PostgreSQL...")
    await init_redis(settings.redis_url)
    await database.init_db(settings.database_url)
    logger.info("Ready.")

    yield

    logger.info("Shutting down...")
    await close_redis()
    await database.close_db()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Detect throwaway and invalid email addresses at signup. "
            "Stop free trial abuse. Protect your paid user base."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS: empty CORS_ALLOW_ORIGINS → wildcard (dev). Production MUST set it.
    origins_raw = settings.cors_allow_origins.strip()
    allow_origins: list[str] = (
        [o.strip() for o in origins_raw.split(",") if o.strip()] if origins_raw else ["*"]
    )
    # Credentials (Authorization header) can't be used with wildcard origin per spec.
    allow_credentials = origins_raw != ""

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    # ── Request ID middleware (per blueprint §15) ─────────────────────────────
    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):
        request.state.request_id = f"req_{secrets.token_hex(6)}"
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(check.router, prefix="/v1")
    app.include_router(report.router, prefix="/v1")
    app.include_router(auth.router, prefix="/v1")
    app.include_router(oauth.router, prefix="/v1")
    app.include_router(keys.router, prefix="/v1")
    app.include_router(usage.router, prefix="/v1")
    app.include_router(billing.router, prefix="/v1")
    # webhooks router declares its own /v1/webhooks/* paths.
    app.include_router(webhooks.router)

    # ── Unified error envelope ────────────────────────────────────────────────
    # Every error response has the same shape:
    #   {"error": {"code": "...", "http_status": N, "message": "...",
    #              "request_id": "req_...", "docs_url": "..."}}
    # No raw FastAPI detail[] arrays leak through.

    def _envelope(detail: ErrorDetail, request_id: str) -> dict:
        detail.request_id = request_id or detail.request_id
        return {"error": detail.model_dump(exclude_none=True)}

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        req_id = getattr(request.state, "request_id", "")
        payload = exc.detail
        # Legacy routes raise HTTPException(detail=error_factory().model_dump())
        # so `payload` is already an ErrorDetail dict. Re-hydrate then inject
        # the request_id and return in the envelope.
        if isinstance(payload, dict) and "code" in payload and "http_status" in payload:
            detail = ErrorDetail(**payload)
        else:
            detail = ErrorDetail(
                code="http_error",
                http_status=exc.status_code,
                message=str(payload) if payload else "Request failed.",
            )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(detail, req_id),
            headers={"X-Request-Id": req_id},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        req_id = getattr(request.state, "request_id", "")
        errs = exc.errors() or []
        if errs:
            first = errs[0]
            loc = " / ".join(str(p) for p in first.get("loc", []) if p != "body")
            msg = f"{loc}: {first.get('msg', 'Invalid input')}" if loc else first.get("msg", "Invalid input")
        else:
            msg = "Invalid request body."
        return JSONResponse(
            status_code=422,
            content=_envelope(validation_error(msg), req_id),
            headers={"X-Request-Id": req_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        req_id = getattr(request.state, "request_id", "")
        return JSONResponse(
            status_code=500,
            content=_envelope(internal_error(), req_id),
            headers={"X-Request-Id": req_id},
        )

    return app


app = create_app()
