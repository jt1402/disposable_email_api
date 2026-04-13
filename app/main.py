"""
FastAPI application entry point.

Startup: initialise Redis + PostgreSQL connections.
Shutdown: gracefully close connections.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.routes import check, health, report, webhooks
from app.core.config import get_settings
from app.models.errors import internal_error
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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tighten for production
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(check.router, prefix="/v1")
    app.include_router(report.router, prefix="/v1")
    app.include_router(webhooks.router)

    # ── Global exception handler ──────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content=internal_error().model_dump())

    return app


app = create_app()
