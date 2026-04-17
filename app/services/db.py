"""
PostgreSQL async engine via SQLAlchemy 2.0.

Tables:
  customers      — one row per Stripe customer
  api_keys       — one per Unkey key, linked to customer + tier
  domain_reports — customer feedback via POST /v1/report
  checks         — append-only log, one row per /v1/check request (domain only)
  domain_stats   — rolled-up per-domain counters, fuels auto-blocklist promotion
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True)
    unkey_key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tier: Mapped[str] = mapped_column(String(32), default="free")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DomainReport(Base):
    __tablename__ = "domain_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    reporter_key_id: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32))  # confirmed_throwaway | confirmed_legitimate
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class Check(Base):
    """
    Append-only log of every /v1/check request. Domain only — no emails.
    Fuels the dashboard (per-customer check counts, block rates, top domains)
    and the auto-blocklist promotion pipeline.
    """
    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    api_key_id: Mapped[str] = mapped_column(String(64), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    recommendation: Mapped[str] = mapped_column(String(32))
    path_taken: Mapped[str] = mapped_column(String(16), default="standard")
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True,
    )


class DomainStats(Base):
    """
    Rolled-up counters per unique domain. One row per domain, upserted on every
    check. Feeds auto-blocklist promotion: domains with enough cross-customer
    evidence get added to Redis blocklist at medium confidence.
    """
    __tablename__ = "domain_stats"

    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True,
    )
    total_checks: Mapped[int] = mapped_column(BigInteger, default=0)
    blocks: Mapped[int] = mapped_column(BigInteger, default=0)
    verify_manually: Mapped[int] = mapped_column(BigInteger, default=0)
    allow_with_flag: Mapped[int] = mapped_column(BigInteger, default=0)
    allows: Mapped[int] = mapped_column(BigInteger, default=0)
    avg_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_recommendation: Mapped[str] = mapped_column(String(32), default="")
    reports_throwaway: Mapped[int] = mapped_column(Integer, default=0)
    reports_legitimate: Mapped[int] = mapped_column(Integer, default=0)
    # auto-promotion state (Tier C — cron sets these later)
    promoted_to_blocklist: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    promotion_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)


async def init_db(database_url: str) -> None:
    global _engine, _session_factory
    # Railway provides postgresql:// but asyncpg requires postgresql+asyncpg://
    if database_url.startswith("postgresql://") or database_url.startswith("postgres://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1).replace("postgres://", "postgresql+asyncpg://", 1)
    _engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    global _engine
    if _engine:
        await _engine.dispose()


def get_session() -> AsyncSession:
    if _session_factory is None:
        raise RuntimeError("Database not initialised. Call init_db() at startup.")
    return _session_factory()
