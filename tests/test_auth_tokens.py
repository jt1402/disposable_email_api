"""
Auth token primitives — pure functions only (no DB).

The DB-touching flows (signup → email → verify → session) are exercised
in an integration test that boots the full app; this file locks in the
cryptographic guarantees of the token utilities themselves.
"""

import hashlib

from app.services.auth import generate_token, hash_token


def test_generate_token_returns_raw_and_hash_pair() -> None:
    raw, token_hash = generate_token()
    assert raw
    assert token_hash
    assert hash_token(raw) == token_hash


def test_generate_token_is_unique_across_calls() -> None:
    seen_raw = set()
    seen_hash = set()
    for _ in range(200):
        raw, token_hash = generate_token()
        assert raw not in seen_raw
        assert token_hash not in seen_hash
        seen_raw.add(raw)
        seen_hash.add(token_hash)


def test_hash_token_is_sha256_hex() -> None:
    raw = "anything"
    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert hash_token(raw) == expected
    assert len(hash_token(raw)) == 64  # sha256 hex = 64 chars


def test_hash_token_is_deterministic() -> None:
    assert hash_token("same-input") == hash_token("same-input")
    assert hash_token("a") != hash_token("b")


def test_generate_token_has_high_entropy() -> None:
    """secrets.token_urlsafe(32) → ~43 base64url chars, plenty of entropy."""
    raw, _ = generate_token()
    assert len(raw) >= 32
    # base64url alphabet only
    assert all(c.isalnum() or c in "-_" for c in raw)
