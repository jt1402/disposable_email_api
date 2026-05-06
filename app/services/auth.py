"""
Authentication primitives — magic-link signup/login and session lifecycle.

Token model:
  - Magic links and sessions both use random 32-byte values (base64url-encoded).
  - Only sha256 hashes are persisted. A DB leak cannot be used to impersonate.
  - Magic links are single-use (marked via used_at) and short-lived.
  - Sessions are long-lived but revocable (revoked_at).

All functions return primitive dataclasses rather than ORM rows so the routes
don't need to worry about detached-instance errors.
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete as sa_delete, select

from app.core.config import get_settings
from app.services import db, unkey

logger = logging.getLogger(__name__)


# ── Token utilities ─────────────────────────────────────────────────────────


def generate_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hex). The raw goes in email/cookie, hash in DB."""
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass
class UserDTO:
    id: int
    email: str
    email_verified_at: datetime | None
    created_at: datetime


@dataclass
class SessionIssueResult:
    token: str
    expires_at: datetime


def _user_to_dto(u: db.User) -> UserDTO:
    return UserDTO(
        id=u.id,
        email=u.email,
        email_verified_at=u.email_verified_at,
        created_at=u.created_at,
    )


# ── Users ────────────────────────────────────────────────────────────────────


async def get_or_create_user(email: str) -> UserDTO:
    """
    Idempotent by email. Returns the user whether newly created or already
    existed. Email is normalised to lowercase.
    """
    email = email.strip().lower()
    async with db.get_session() as s:
        result = await s.execute(select(db.User).where(db.User.email == email))
        user = result.scalar_one_or_none()
        if user is None:
            from app.core.config import get_settings
            user = db.User(
                email=email,
                credit_balance_checks=get_settings().free_signup_credits,
            )
            s.add(user)
            await s.commit()
            await s.refresh(user)
        return _user_to_dto(user)


async def get_user_by_id(user_id: int) -> UserDTO | None:
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        return _user_to_dto(user) if user else None


async def mark_email_verified(user_id: int) -> None:
    async with db.get_session() as s:
        user = await s.get(db.User, user_id)
        if user and user.email_verified_at is None:
            user.email_verified_at = datetime.now(UTC)
            await s.commit()


# ── Magic links ──────────────────────────────────────────────────────────────


async def issue_magic_link(
    user_id: int, purpose: str, ip: str | None = None
) -> str:
    """Create a single-use token for signup_verify or login. Returns raw token."""
    settings = get_settings()
    raw, token_hash = generate_token()
    expires_at = datetime.now(UTC) + timedelta(
        minutes=settings.magic_link_ttl_minutes
    )
    async with db.get_session() as s:
        s.add(
            db.MagicLinkToken(
                user_id=user_id,
                token_hash=token_hash,
                purpose=purpose,
                expires_at=expires_at,
                ip=ip,
            )
        )
        await s.commit()
    return raw


async def consume_magic_link(raw_token: str) -> tuple[UserDTO, str] | None:
    """
    Validate and burn a magic-link token. Returns (user, purpose) on success,
    None on expired / used / unknown. Single-use: marks used_at inside the
    transaction so concurrent clicks lose.
    """
    token_hash = hash_token(raw_token)
    now = datetime.now(UTC)
    async with db.get_session() as s:
        result = await s.execute(
            select(db.MagicLinkToken).where(db.MagicLinkToken.token_hash == token_hash)
        )
        token = result.scalar_one_or_none()
        if token is None or token.used_at is not None or token.expires_at < now:
            return None
        token.used_at = now
        user = await s.get(db.User, token.user_id)
        if user is None:
            return None
        await s.commit()
        return _user_to_dto(user), token.purpose


# ── Sessions ─────────────────────────────────────────────────────────────────


async def issue_session(
    user_id: int, ip: str | None = None, user_agent: str | None = None
) -> SessionIssueResult:
    """Create a new session. Returns the raw token (store in cookie) + expiry."""
    settings = get_settings()
    raw, token_hash = generate_token()
    expires_at = datetime.now(UTC) + timedelta(days=settings.session_ttl_days)
    async with db.get_session() as s:
        s.add(
            db.UserSession(
                user_id=user_id,
                token_hash=token_hash,
                expires_at=expires_at,
                ip=ip,
                user_agent=(user_agent or "")[:500] or None,
            )
        )
        await s.commit()
    return SessionIssueResult(token=raw, expires_at=expires_at)


async def resolve_session(raw_token: str) -> UserDTO | None:
    """Look up a session by raw token. Returns the user if active."""
    token_hash = hash_token(raw_token)
    now = datetime.now(UTC)
    async with db.get_session() as s:
        result = await s.execute(
            select(db.UserSession).where(db.UserSession.token_hash == token_hash)
        )
        sess = result.scalar_one_or_none()
        if sess is None or sess.revoked_at is not None or sess.expires_at < now:
            return None
        user = await s.get(db.User, sess.user_id)
        return _user_to_dto(user) if user else None


async def revoke_session(raw_token: str) -> bool:
    """Mark a session revoked. Idempotent; returns True if a session was found."""
    token_hash = hash_token(raw_token)
    async with db.get_session() as s:
        result = await s.execute(
            select(db.UserSession).where(db.UserSession.token_hash == token_hash)
        )
        sess = result.scalar_one_or_none()
        if sess is None:
            return False
        if sess.revoked_at is None:
            sess.revoked_at = datetime.now(UTC)
            await s.commit()
        return True


# ── Account deletion ────────────────────────────────────────────────────────


async def delete_user(user_id: int) -> None:
    """
    Hard-delete a user and all per-user state: API keys (with Unkey revoke),
    sessions, and magic-link tokens. The append-only `checks` table is left
    intact — domain-only rows have no PII and feed the auto-blocklist
    pipeline. The Polar customer record (if any) also remains for accounting
    and refund history.

    Unkey revokes are best-effort: a failure on Unkey's side logs but does
    not block account deletion. Worst case a key remains live in Unkey but
    can never authenticate against us (the local row is gone).
    """
    async with db.get_session() as s:
        rows = (await s.execute(
            select(db.ApiKey.unkey_key_id).where(db.ApiKey.user_id == user_id)
        )).scalars().all()
    for unkey_key_id in rows:
        if not unkey_key_id:
            continue
        try:
            await unkey.revoke_key(unkey_key_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Unkey revoke failed during account deletion (user=%s, key=%s): %s",
                user_id, unkey_key_id, exc,
            )

    async with db.get_session() as s:
        await s.execute(sa_delete(db.ApiKey).where(db.ApiKey.user_id == user_id))
        await s.execute(sa_delete(db.UserSession).where(db.UserSession.user_id == user_id))
        await s.execute(sa_delete(db.MagicLinkToken).where(db.MagicLinkToken.user_id == user_id))
        await s.execute(sa_delete(db.User).where(db.User.id == user_id))
        await s.commit()
    logger.info("Deleted user %s and associated keys/sessions/tokens", user_id)
