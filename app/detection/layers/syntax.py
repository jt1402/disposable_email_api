"""
Layer 1 — Syntax Validation (~1ms)

Pure in-memory checks. No I/O. Run before anything touches Redis or the network.
Catches: malformed addresses, consecutive dots, unicode homographs, length violations.
"""

import re
import unicodedata
from dataclasses import dataclass, field

# RFC 5321 local part: printable ASCII minus special chars that need quoting
_LOCAL_SAFE_CHARS = re.compile(r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+$')

# Labels in the domain part
_DOMAIN_LABEL = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

# Cyrillic + Greek characters that are visually identical to Latin — homograph attack vectors.
# Source: Unicode Consortium confusables (curated subset for email domains).
_HOMOGRAPH_CHARS: frozenset[str] = frozenset(
    "аеоркухівсСАВЕНКМОРТХ"   # Cyrillic lookalikes
    "αβεηιοτυχΑΒΕΗΙΚΜΝΟΡΤΥΧ"  # Greek lookalikes
)


@dataclass
class SyntaxResult:
    valid: bool
    signals: list[str] = field(default_factory=list)
    local: str = ""
    domain: str = ""


def validate(email: str) -> SyntaxResult:
    # ── 1. NFKC normalise first so composed chars don't slip through ──────────
    try:
        email = unicodedata.normalize("NFKC", email).strip()
    except (TypeError, ValueError):
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 2. Overall length (RFC 5321 §4.5.3) ──────────────────────────────────
    if not email or len(email) > 254:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 3. Split on @ — exactly one required ─────────────────────────────────
    at_count = email.count("@")
    if at_count != 1:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    local, domain = email.split("@", 1)

    # ── 4. Local part length (RFC 5321 §4.5.3) ───────────────────────────────
    if not local or len(local) > 64:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 5. Domain length ──────────────────────────────────────────────────────
    if not domain or len(domain) > 255:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    signals: list[str] = []

    # ── 6. Local part: dot rules ──────────────────────────────────────────────
    if local.startswith(".") or local.endswith("."):
        return SyntaxResult(valid=False, signals=["invalid_syntax"])
    if ".." in local:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 7. Local part: character set (unquoted form only — covers 99%+ cases) ─
    if not _LOCAL_SAFE_CHARS.match(local):
        # Could be a legitimate quoted local part ("john doe"@example.com),
        # but these are vanishingly rare and almost never disposable-relevant.
        # Flag rather than hard-reject so caller can decide.
        signals.append("non_standard_local")

    # ── 8. Role-based addresses ───────────────────────────────────────────────
    ROLE_PREFIXES = {
        "admin", "administrator", "noreply", "no-reply", "postmaster",
        "abuse", "hostmaster", "webmaster", "support", "info", "test",
        "root", "mailer-daemon", "null", "nobody",
    }
    if local.lower() in ROLE_PREFIXES or local.lower().split("+")[0] in ROLE_PREFIXES:
        signals.append("role_based_address")

    # ── 9. Domain: must have at least one dot ─────────────────────────────────
    if "." not in domain:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 10. Domain: dot rules ─────────────────────────────────────────────────
    if domain.startswith(".") or domain.endswith("."):
        return SyntaxResult(valid=False, signals=["invalid_syntax"])
    if ".." in domain:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 11. Unicode / IDN domain check ───────────────────────────────────────
    if not domain.isascii():
        # Check for homograph characters (Cyrillic/Greek visual clones of Latin)
        if any(c in _HOMOGRAPH_CHARS for c in domain):
            signals.append("unicode_homograph_domain")
        else:
            signals.append("non_ascii_domain")
        # Attempt IDNA encoding to validate it's a real IDN domain
        try:
            domain.encode("idna")
        except (UnicodeError, UnicodeDecodeError):
            return SyntaxResult(valid=False, signals=["invalid_syntax"])

    # ── 12. Validate each domain label ───────────────────────────────────────
    labels = domain.split(".")
    if len(labels) < 2:
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return SyntaxResult(valid=False, signals=["invalid_syntax"])

    for label in labels[:-1]:
        if not label:
            return SyntaxResult(valid=False, signals=["invalid_syntax"])
        ascii_label = label
        if not ascii_label.isascii():
            try:
                ascii_label = label.encode("idna").decode("ascii").lstrip("xn--")
            except (UnicodeError, UnicodeDecodeError):
                return SyntaxResult(valid=False, signals=["invalid_syntax"])
        if not _DOMAIN_LABEL.match(ascii_label):
            return SyntaxResult(valid=False, signals=["invalid_syntax"])

    return SyntaxResult(valid=True, signals=signals, local=local, domain=domain.lower())
