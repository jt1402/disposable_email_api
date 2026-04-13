"""
Layer 1 — Syntax validation tests.

Tests every edge case mentioned in the blueprint plus RFC 5321/5322 corner cases.
All in-memory, no I/O, runs in <1ms per test.
"""

import pytest

from app.detection.layers.syntax import validate


# ── Valid addresses ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("email", [
    "user@example.com",
    "user+tag@example.com",
    "user.name@example.co.uk",
    "user123@sub.domain.com",
    "a@b.io",
    "USER@EXAMPLE.COM",
    "user@xn--nxasmq6b.com",  # valid IDN domain in punycode
])
def test_valid_emails(email: str) -> None:
    result = validate(email)
    assert result.valid, f"Expected {email!r} to be valid, got signals: {result.signals}"


# ── Invalid addresses ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("email", [
    "",                         # empty
    "notanemail",               # no @
    "@example.com",             # no local part
    "user@",                    # no domain
    "user@.com",                # domain starts with dot
    "user@com",                 # no dot in domain
    "user@@example.com",        # two @
    ".user@example.com",        # leading dot in local
    "user.@example.com",        # trailing dot in local
    "us..er@example.com",       # consecutive dots in local
    "user@exam..ple.com",       # consecutive dots in domain
    "user@example.com" + "x" * 255,  # too long overall
    "a" * 65 + "@example.com",  # local part too long
    "user@example",             # TLD missing
    "user@example.123",         # numeric TLD
])
def test_invalid_emails(email: str) -> None:
    result = validate(email)
    assert not result.valid, f"Expected {email!r} to be invalid"
    assert "invalid_syntax" in result.signals


# ── Role-based addresses ──────────────────────────────────────────────────────
@pytest.mark.parametrize("email", [
    "admin@example.com",
    "noreply@example.com",
    "no-reply@example.com",
    "support@example.com",
    "test@example.com",
    "info@example.com",
    "postmaster@example.com",
])
def test_role_based_flagged(email: str) -> None:
    result = validate(email)
    assert result.valid
    assert "role_based_address" in result.signals


# ── Homograph detection ───────────────────────────────────────────────────────
def test_cyrillic_homograph() -> None:
    # а (U+0430 Cyrillic) looks like Latin a
    cyrillic_email = "user@exаmple.com"  # а is Cyrillic
    result = validate(cyrillic_email)
    # Should be valid syntax but flagged
    assert "unicode_homograph_domain" in result.signals


# ── Domain extraction ─────────────────────────────────────────────────────────
def test_domain_lowercased() -> None:
    result = validate("User@EXAMPLE.COM")
    assert result.valid
    assert result.domain == "example.com"


def test_local_preserved() -> None:
    result = validate("UserName@example.com")
    assert result.valid
    assert result.local == "UserName"  # local part case preserved
