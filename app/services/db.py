"""
PostgreSQL async engine via SQLAlchemy 2.0.

Tables:
  users              — dashboard user accounts (magic-link signup, optional Stripe link)
  user_sessions      — active session tokens (hashed) per user
  magic_link_tokens  — single-use tokens for signup verification / passwordless login
  api_keys           — one per Unkey key, linked to user
  domain_reports     — customer feedback via POST /v1/report
  checks             — append-only log, one row per /v1/check request (domain only)
  domain_stats       — rolled-up per-domain counters, fuels auto-blocklist promotion

NOTE: the `customers` table from an earlier iteration was collapsed into `users`.
Running a pre-existing dev DB may still have a stray `customers` table — the
first Alembic migration will drop it. `Base.metadata.create_all` does NOT drop
tables that were removed from the models.
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    pass


class User(Base):
    """
    Dashboard user account. Created via magic-link signup from the landing page.
    A user can own multiple API keys; Stripe customer link is populated on first
    paid checkout (nullable until then — users with only the signup grant have
    no Stripe presence).
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )
    # Pre-paid checks remaining. Decremented on every successful /v1/check;
    # topped up by bundle purchases via the Stripe webhook. New signups get a
    # bootstrap grant of settings.free_signup_credits (default 100).
    credit_balance_checks: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class UserSession(Base):
    """
    Active session for a user. Token is a random 32-byte value; only its
    sha256 hash is stored. Sessions are revocable (revoked_at) and expire
    (expires_at). Lookup is by hash, so a stolen DB dump cannot impersonate.
    """
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)


class MagicLinkToken(Base):
    """
    Single-use token emailed to the user for signup verification or passwordless
    login. Only sha256 hash is stored; raw token lives only in the email link.
    Tokens expire after MAGIC_LINK_TTL_MINUTES and are consumed on first use.
    """
    __tablename__ = "magic_link_tokens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32))  # "signup_verify" | "login"
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class ApiKey(Base):
    """
    Local mirror of an Unkey key. The secret lives only in Unkey; we keep the
    public-safe metadata (name, last_used_at, owner) here so the dashboard
    can list/revoke without hammering Unkey.

    `unkey_key_prefix` stores the first 8 chars of the key (e.g. "dc_abcd")
    so the dashboard can show "dc_abcd…" without ever persisting the full key.
    """
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    unkey_key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    unkey_key_prefix: Mapped[str] = mapped_column(String(16), default="")
    name: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
    # Schema is owned by Alembic: `alembic upgrade head` runs on container start.


async def close_db() -> None:
    global _engine
    if _engine:
        await _engine.dispose()


def get_session() -> AsyncSession:
    if _session_factory is None:
        raise RuntimeError("Database not initialised. Call init_db() at startup.")
    return _session_factory()
