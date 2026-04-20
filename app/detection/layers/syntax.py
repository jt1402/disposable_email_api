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

# TLDs with elevated abuse rates. Sources: Spamhaus, public phishing databases,
# Freenom's former free-TLD family. .top and .cyou added based on blueprint's
# abuse-TLD research. Not a ban — just +12 points toward the risk side.
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf",       # Freenom (many free / disposable registrations)
    "xyz",                         # cheap and heavily abused
    "top", "loan", "work", "click", "link",
    "cyou", "rest", "icu", "buzz",
    "men", "bid", "racing", "stream", "download",
    "zip", "mov",                  # Google's ambiguous TLDs
})

# Generated-domain patterns — sld (second-level domain) that looks machine-made.
# Matches: 4+ consecutive digits, long strings with no vowels, or alternating
# letter/digit runs. False-positive rate on legit domains is low because short
# legit names (<8 chars) don't match and we only run against the SLD.
_DIGIT_RUN = re.compile(r"\d{4,}")
_NO_VOWELS = re.compile(r"^[bcdfghjklmnpqrstvwxyz]{8,}$", re.IGNORECASE)
_ALTERNATING = re.compile(r"(?:[a-z]\d){4,}", re.IGNORECASE)


def _looks_generated(sld: str) -> bool:
    """Heuristic: does this SLD look machine-generated?"""
    if len(sld) < 8:
        return False
    if _DIGIT_RUN.search(sld):
        return True
    if _ALTERNATING.search(sld):
        return True
    # Long all-consonant string (e.g. xkfhjq...)
    cleaned = sld.replace("-", "")
    if _NO_VOWELS.match(cleaned):
        return True
    return False


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
        # Convert to punycode so downstream DNS/WHOIS lookups operate on the
        # actual DNS name (xn--...) rather than the unicode glyphs. This
        # prevents homograph attacks from piggybacking on the lookalike
        # domain's age / trust signals.
        try:
            domain = domain.encode("idna").decode("ascii")
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

    # ── 13. Suspicious TLD + generated-domain pattern ───────────────────────
    # These run against the final (potentially punycode) form of the domain,
    # so homograph-encoded names get their TLD check too.
    final_domain = domain.lower()
    final_labels = final_domain.split(".")
    final_tld = final_labels[-1]
    final_sld = final_labels[-2] if len(final_labels) >= 2 else ""

    if final_tld in _SUSPICIOUS_TLDS:
        signals.append("suspicious_tld")

    if _looks_generated(final_sld):
        signals.append("generated_domain_pattern")

    return SyntaxResult(valid=True, signals=signals, local=local, domain=final_domain)
