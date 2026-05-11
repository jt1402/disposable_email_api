"""
Scoring Engine — five-layer evidence model per technical blueprint §1.

Not simple addition. Structure:
  Layer 1  Hard disqualifiers — immediate exit with score 100
  Layer 2  Strong evidence   — high-weight individual or named-compound signals
  Layer 3  Corroborating     — medium-weight, compound together (1.3x/1.6x/1.9x)
  Layer 4  Trust builders    — NEGATIVE weights, actively reduce risk

Trust signals are what makes catch-all detection work correctly: a catch-all on a
6-year-old domain with SPF+DKIM+DMARC should score LOW, not medium.

Confidence separate from score: score=85 conf=0.45 → 'allow_with_flag', not 'block'.
"""

from dataclasses import dataclass, field

from app.models.check import (
    ConfidenceLevel,
    ModelPhase,
    Recommendation,
    RiskLevel,
    RiskProfile,
)

# ── Signal registry ───────────────────────────────────────────────────────────
# Each signal has tier + weight + category + description. Engine uses this to
# build Signal objects. Weights come from blueprint §1 and academic-derived
# priors §5.

TIER_HARD = "hard"
TIER_STRONG = "strong"
TIER_CORROBORATING = "corroborating"
TIER_TRUST = "trust"

CATEGORY_SYNTAX = "syntax"
CATEGORY_BLOCKLIST = "blocklist"
CATEGORY_INFRASTRUCTURE = "domain_infrastructure"
CATEGORY_SMTP = "smtp_analysis"
CATEGORY_BEHAVIORAL = "behavioral"


@dataclass(frozen=True)
class SignalDef:
    name: str
    tier: str
    category: str
    weight: int              # positive for risk, negative for trust
    description: str


SIGNAL_REGISTRY: dict[str, SignalDef] = {
    # ── Layer 1: Hard disqualifiers (immediate 100) ─────────────────────────
    "invalid_syntax": SignalDef(
        "invalid_syntax", TIER_HARD, CATEGORY_SYNTAX, 100,
        "Email does not pass RFC 5322 syntax validation.",
    ),
    "no_mx_records": SignalDef(
        "no_mx_records", TIER_HARD, CATEGORY_INFRASTRUCTURE, 100,
        "Domain has no MX records. Cannot receive email.",
    ),
    "known_disposable_domain_high_confidence": SignalDef(
        "known_disposable_domain_high_confidence", TIER_HARD, CATEGORY_BLOCKLIST, 100,
        "Domain is on the blocklist with >0.95 confidence.",
    ),
    "domain_does_not_exist": SignalDef(
        "domain_does_not_exist", TIER_HARD, CATEGORY_INFRASTRUCTURE, 100,
        "Domain does not exist (DNS NXDOMAIN).",
    ),

    # ── Layer 2: Strong evidence (individual + named compounds) ─────────────
    "known_disposable_domain": SignalDef(
        "known_disposable_domain", TIER_STRONG, CATEGORY_BLOCKLIST, 75,
        "Domain is on the blocklist (confidence 0.70-0.95).",
    ),
    "catch_all_new_domain": SignalDef(
        "catch_all_new_domain", TIER_STRONG, CATEGORY_SMTP, 85,
        "Catch-all detected on a domain registered less than 30 days ago. "
        "Near-certain fraud pattern.",
    ),
    "unicode_homograph_domain": SignalDef(
        "unicode_homograph_domain", TIER_STRONG, CATEGORY_SYNTAX, 70,
        "Domain contains Cyrillic or Greek characters that visually mimic Latin letters.",
    ),
    "domain_age_under_7_days": SignalDef(
        "domain_age_under_7_days", TIER_STRONG, CATEGORY_INFRASTRUCTURE, 68,
        "Domain registered less than 7 days ago. "
        "Academic research: 87% fraud rate in abuse contexts.",
    ),
    "mx_known_disposable_infrastructure": SignalDef(
        "mx_known_disposable_infrastructure", TIER_STRONG, CATEGORY_INFRASTRUCTURE, 75,
        "MX record points to a known disposable email provider.",
    ),
    "cross_customer_abuse_pattern": SignalDef(
        "cross_customer_abuse_pattern", TIER_STRONG, CATEGORY_BEHAVIORAL, 35,
        "Multiple independent customers are querying this domain — "
        "likely a fresh disposable provider not yet on the blocklist.",
    ),

    # ── Layer 3: Corroborating signals (compound together) ──────────────────
    "new_domain_30d": SignalDef(
        "new_domain_30d", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 25,
        "Domain registered 7-30 days ago.",
    ),
    "new_domain_90d": SignalDef(
        "new_domain_90d", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 12,
        "Domain registered 30-90 days ago.",
    ),
    "domain_age_unknown": SignalDef(
        "domain_age_unknown", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 8,
        "Unable to determine domain age (WHOIS unavailable).",
    ),
    "suspicious_mx_infrastructure": SignalDef(
        "suspicious_mx_infrastructure", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 30,
        "MX server is shared with multiple known-disposable domains.",
    ),
    "catch_all_domain": SignalDef(
        "catch_all_domain", TIER_CORROBORATING, CATEGORY_SMTP, 30,
        "Domain accepts email for any address. Can produce verified-but-unreachable users.",
    ),
    "abuse_pattern_detected": SignalDef(
        "abuse_pattern_detected", TIER_CORROBORATING, CATEGORY_BEHAVIORAL, 25,
        "Unusually high query volume to this domain in the last 24 hours.",
    ),
    "role_based_address": SignalDef(
        "role_based_address", TIER_CORROBORATING, CATEGORY_SYNTAX, 12,
        "Local part is a role-based address (admin, noreply, support, etc.).",
    ),
    "non_ascii_domain": SignalDef(
        "non_ascii_domain", TIER_CORROBORATING, CATEGORY_SYNTAX, 15,
        "Domain contains non-ASCII characters (IDN).",
    ),
    "non_standard_local": SignalDef(
        "non_standard_local", TIER_CORROBORATING, CATEGORY_SYNTAX, 10,
        "Local part contains characters outside the standard RFC 5321 charset.",
    ),
    "no_spf_record": SignalDef(
        "no_spf_record", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 10,
        "Domain has no SPF record.",
    ),
    "no_dmarc_record": SignalDef(
        "no_dmarc_record", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 8,
        "Domain has no DMARC record.",
    ),
    "suspicious_tld": SignalDef(
        "suspicious_tld", TIER_CORROBORATING, CATEGORY_SYNTAX, 12,
        "Domain uses a TLD with elevated abuse rates (.xyz, .tk, .ml, .ga, .cf, etc.).",
    ),
    "generated_domain_pattern": SignalDef(
        "generated_domain_pattern", TIER_CORROBORATING, CATEGORY_SYNTAX, 20,
        "Domain name matches a machine-generated or algorithmic pattern "
        "(long digit runs, random-looking character sequences, or hash-like names).",
    ),
    "random_local_part_pattern": SignalDef(
        "random_local_part_pattern", TIER_CORROBORATING, CATEGORY_SYNTAX, 25,
        "Local part looks machine-generated — high Shannon entropy, low vowel ratio, "
        "no separators, mixed letters and digits. Common bot bypass on legitimate "
        "providers (e.g. q9zk3v7x2m@gmail.com).",
    ),
    "unusual_local_chars": SignalDef(
        "unusual_local_chars", TIER_CORROBORATING, CATEGORY_SYNTAX, 18,
        "Local part contains RFC-5321-valid but vanishingly rare characters "
        "(!, #, $, %, &, ', *, /, =, ?, ^, `, {, |, }, ~). Real email clients "
        "almost never produce these — strong bot / test-data indicator.",
    ),
    "impossible_address_on_legit_provider": SignalDef(
        "impossible_address_on_legit_provider", TIER_STRONG, CATEGORY_SYNTAX, 85,
        "Local part uses characters that the major providers (Gmail, Outlook, "
        "Yahoo, iCloud, Proton) explicitly disallow at signup. The address "
        "provably cannot exist on this domain.",
    ),
    "custom_allowlist_match": SignalDef(
        "custom_allowlist_match", TIER_TRUST, CATEGORY_SYNTAX, -100,
        "Domain is on the customer's custom allowlist — verdict forced to allow.",
    ),
    "custom_blocklist_match": SignalDef(
        "custom_blocklist_match", TIER_STRONG, CATEGORY_SYNTAX, 100,
        "Domain is on the customer's custom blocklist — verdict forced to block.",
    ),
    "bulk_registrar": SignalDef(
        "bulk_registrar", TIER_CORROBORATING, CATEGORY_INFRASTRUCTURE, 15,
        "Domain was registered through a bulk / cheap-tier registrar frequently "
        "used for disposable email infrastructure.",
    ),

    # ── Layer 4: Trust signals (negative weights) ──────────────────────────
    "domain_age_over_5_years": SignalDef(
        "domain_age_over_5_years", TIER_TRUST, CATEGORY_INFRASTRUCTURE, -25,
        "Domain registered more than 5 years ago. Very low fraud base rate.",
    ),
    "domain_age_over_2_years": SignalDef(
        "domain_age_over_2_years", TIER_TRUST, CATEGORY_INFRASTRUCTURE, -15,
        "Domain registered more than 2 years ago.",
    ),
    "spf_dkim_dmarc_all_present": SignalDef(
        "spf_dkim_dmarc_all_present", TIER_TRUST, CATEGORY_INFRASTRUCTURE, -20,
        "Domain has SPF, DKIM, and DMARC all configured — standard for legitimate senders.",
    ),
    "known_legitimate_provider": SignalDef(
        "known_legitimate_provider", TIER_TRUST, CATEGORY_BLOCKLIST, -30,
        "Domain is a major legitimate mail provider (Gmail, Outlook, iCloud, etc.).",
    ),
    "mx_known_legitimate_host": SignalDef(
        "mx_known_legitimate_host", TIER_TRUST, CATEGORY_INFRASTRUCTURE, -15,
        "MX points to a known legitimate host (Google Workspace, Microsoft 365, etc.).",
    ),
    "catch_all_old_established": SignalDef(
        "catch_all_old_established", TIER_TRUST, CATEGORY_SMTP, -15,
        "Catch-all is configured but on a long-established domain — typical B2B pattern.",
    ),
}


def get_signal_def(name: str) -> SignalDef | None:
    return SIGNAL_REGISTRY.get(name)


# ── Hard disqualifier detection ───────────────────────────────────────────────

HARD_DISQUALIFIERS: frozenset[str] = frozenset(
    name for name, sd in SIGNAL_REGISTRY.items() if sd.tier == TIER_HARD
)


def is_hard_disqualifier(signal_name: str) -> bool:
    return signal_name in HARD_DISQUALIFIERS


# ── Compounding logic (Layer 3) ───────────────────────────────────────────────

def compound_score(corroborating_signals: list[str]) -> tuple[int, int]:
    """
    Returns (compounded_score, bonus_from_compounding).

    Each additional independent corroborating signal adds MORE than its face
    value — because independent confirmation is non-linear evidence.

    Signal 1 counts 1.0x.  Signal 2: 1.3x.  Signal 3: 1.6x.  Signal 4: 1.9x...

    Capped at 95 — leaves room for trust signals to matter.
    """
    if not corroborating_signals:
        return 0, 0

    weights = sorted(
        [SIGNAL_REGISTRY[s].weight for s in corroborating_signals if s in SIGNAL_REGISTRY],
        reverse=True,
    )
    if not weights:
        return 0, 0

    face_value_sum = sum(weights)
    score: float = weights[0]
    for i, weight in enumerate(weights[1:], 1):
        score += weight * (1 + 0.3 * i)

    clamped = min(int(round(score)), 95)
    bonus = max(0, clamped - face_value_sum)
    return clamped, bonus


# ── Confidence calculation ────────────────────────────────────────────────────

CONFIDENCE_PENALTIES: dict[str, float] = {
    "smtp_probe_timeout": -0.15,
    "whois_lookup_failed": -0.10,
    "mx_lookup_timeout": -0.12,
    "dns_partial_response": -0.08,
    "behavioral_no_history": -0.05,
    "network_signals_empty": -0.05,
    "catchall_skipped": -0.10,
    "spf_lookup_failed": -0.05,
    "dmarc_lookup_failed": -0.05,
}


def calculate_confidence(failed_or_inconclusive: list[str]) -> float:
    """Start at 1.0, subtract for each check that didn't provide a signal."""
    confidence = 1.0
    for reason in failed_or_inconclusive:
        confidence += CONFIDENCE_PENALTIES.get(reason, -0.05)
    return max(confidence, 0.30)


def confidence_level(confidence: float) -> ConfidenceLevel:
    if confidence >= 0.80:
        return ConfidenceLevel.HIGH
    if confidence >= 0.55:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


# ── Risk profiles ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProfileThresholds:
    block: int
    flag: int
    confidence_gate: float
    estimated_fpr: str
    best_for: str


# Calibrated (steady-state) thresholds
_CALIBRATED: dict[RiskProfile, ProfileThresholds] = {
    RiskProfile.STRICT: ProfileThresholds(
        block=55, flag=35, confidence_gate=0.80,
        estimated_fpr="2-4%", best_for="Fintech, high-value subscriptions",
    ),
    RiskProfile.BALANCED: ProfileThresholds(
        block=70, flag=50, confidence_gate=0.75,
        estimated_fpr="0.5-1%", best_for="SaaS free trials, e-commerce",
    ),
    RiskProfile.PERMISSIVE: ProfileThresholds(
        block=85, flag=65, confidence_gate=0.70,
        estimated_fpr="<0.1%", best_for="Newsletters, communities",
    ),
}

# Bootstrap (month-1) thresholds — stricter to avoid FP before calibration
_BOOTSTRAP: dict[RiskProfile, ProfileThresholds] = {
    RiskProfile.STRICT: ProfileThresholds(
        block=65, flag=45, confidence_gate=0.85,
        estimated_fpr="conservative", best_for="Fintech, high-value subscriptions",
    ),
    RiskProfile.BALANCED: ProfileThresholds(
        block=82, flag=60, confidence_gate=0.85,
        estimated_fpr="conservative", best_for="SaaS free trials, e-commerce",
    ),
    RiskProfile.PERMISSIVE: ProfileThresholds(
        block=92, flag=75, confidence_gate=0.80,
        estimated_fpr="very conservative", best_for="Newsletters, communities",
    ),
}


def thresholds_for(profile: RiskProfile, phase: ModelPhase) -> ProfileThresholds:
    if phase == ModelPhase.BOOTSTRAP:
        return _BOOTSTRAP[profile]
    return _CALIBRATED[profile]


# ── Recommendation logic ──────────────────────────────────────────────────────

_FORCE_FLAG_SIGNALS: frozenset[str] = frozenset({
    # Address looks impossible on this provider, but the rule is provider
    # policy (not RFC) so we don't auto-block — flag for the customer's
    # friction step (email-verification, captcha, etc.). Trust signals can't
    # override it.
    "impossible_address_on_legit_provider",
})


def derive_recommendation(
    score: int,
    confidence: float,
    fired_signal_names: list[str],
    thresholds: ProfileThresholds,
) -> Recommendation:
    """
    Three outcomes — allow / allow_with_flag / block.

    `allow_with_flag` is the safety-margin verdict for everything we suspect
    but can't fully prove. The customer's app routes flagged users through
    its existing verification or friction step (email confirmation, captcha,
    extra KYC, etc.). We don't try to be the inbox.

    Force-flag signals (see _FORCE_FLAG_SIGNALS) bypass the score math
    entirely — they encode third-party rules (e.g., a provider's signup
    policy) we can't verify, so we route the call to the customer instead
    of making it ourselves.
    """
    # Force-flag signals — never auto-block (probable, not provable).
    if any(s in _FORCE_FLAG_SIGNALS for s in fired_signal_names):
        if score >= thresholds.block and confidence >= thresholds.confidence_gate:
            return Recommendation.BLOCK
        return Recommendation.ALLOW_WITH_FLAG

    # High score path
    if score >= thresholds.block:
        if confidence >= thresholds.confidence_gate:
            return Recommendation.BLOCK
        # High score but uncertain — flag rather than auto-blocking. The
        # customer's friction layer protects them; a false-positive auto-block
        # would not.
        return Recommendation.ALLOW_WITH_FLAG

    # Medium score path
    if score >= thresholds.flag:
        return Recommendation.ALLOW_WITH_FLAG

    # Low score but catch-all detected — always surface a flag
    if "catch_all_domain" in fired_signal_names or "catch_all_new_domain" in fired_signal_names:
        return Recommendation.ALLOW_WITH_FLAG

    return Recommendation.ALLOW


# ── Risk level (score-only) ───────────────────────────────────────────────────

def risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ── Summary generation (plain English) ────────────────────────────────────────

def build_summary(
    fired: list[str],
    trust: list[str],
    score: int,
    recommendation: Recommendation,
    domain_age_days: int | None = None,
    catch_all: bool | None = None,
) -> str:
    """One plain-English sentence — no docs needed to understand the verdict."""

    if recommendation == Recommendation.ALLOW and not fired:
        if "known_legitimate_provider" in trust:
            return "Domain is a major legitimate mail provider. Allowed."
        if "mx_known_legitimate_host" in trust or "spf_dkim_dmarc_all_present" in trust:
            return "Domain uses trusted infrastructure and full email authentication. Allowed."
        if "domain_age_over_5_years" in trust:
            return "Domain is well-established with no risk signals. Allowed."
        return "No risk signals detected. Domain appears legitimate."

    if "invalid_syntax" in fired:
        return "Email does not pass syntax validation."

    if "no_mx_records" in fired or "domain_does_not_exist" in fired:
        return "Domain cannot receive email — not a deliverable address."

    if "known_disposable_domain_high_confidence" in fired or "known_disposable_domain" in fired:
        return "Domain is a confirmed disposable email provider."

    if "impossible_address_on_legit_provider" in fired:
        return (
            "Local part uses characters that this provider's signup form "
            "does not accept — the address most likely cannot exist. "
            "Flagged: route through your verification step before delivering."
        )

    parts: list[str] = []
    if domain_age_days is not None and domain_age_days < 30:
        parts.append(f"domain is {domain_age_days} days old")
    elif "domain_age_unknown" in fired:
        parts.append("domain age could not be verified")
    if catch_all is True:
        parts.append("configured as catch-all")
    if "suspicious_mx_infrastructure" in fired or "mx_known_disposable_infrastructure" in fired:
        parts.append("matches known disposable infrastructure")
    if "unicode_homograph_domain" in fired:
        parts.append("uses visually-deceptive unicode characters")
    if "cross_customer_abuse_pattern" in fired or "abuse_pattern_detected" in fired:
        parts.append("shows suspicious traffic patterns")

    if not parts:
        if recommendation == Recommendation.BLOCK:
            return "Multiple risk signals indicate this address is high-risk."
        if recommendation == Recommendation.ALLOW_WITH_FLAG:
            return "Suspicious signals present. Route through your verification step before granting full access."
        return "Low risk."

    joined = ", ".join(parts[:-1]) + (f", and {parts[-1]}" if len(parts) > 1 else parts[0])

    trust_note = ""
    if trust:
        if "known_legitimate_provider" in trust:
            trust_note = " Domain is a major legitimate provider."
        elif "domain_age_over_5_years" in trust:
            trust_note = " However, domain is well-established."

    verdict_clause = {
        Recommendation.BLOCK: "High confidence this address will not reach a real person.",
        Recommendation.ALLOW_WITH_FLAG: "Allow but flag — route through your verification step.",
        Recommendation.ALLOW: "Allowed.",
    }[recommendation]

    return f"Domain {joined}.{trust_note} {verdict_clause}"


# ── Components breakdown (for score.components) ───────────────────────────────

@dataclass
class ScoreBreakdown:
    strong_total: int = 0
    corroborating_raw: int = 0      # sum of face values
    corroborating_compounded: int = 0  # after compounding
    compounding_bonus: int = 0
    trust_adjustments: int = 0
    final_clamped: int = 0
    fired: list[str] = field(default_factory=list)
    trust_fired: list[str] = field(default_factory=list)


def compute_breakdown(signal_names: list[str]) -> ScoreBreakdown:
    """
    Produce a full breakdown. Caller decides hard-disqualifier handling before
    calling this (a hard disqualifier short-circuits to score=100).
    """
    breakdown = ScoreBreakdown()

    strong: list[str] = []
    corroborating: list[str] = []
    trust: list[str] = []

    for name in signal_names:
        sd = SIGNAL_REGISTRY.get(name)
        if not sd:
            continue
        if sd.tier == TIER_STRONG:
            strong.append(name)
        elif sd.tier == TIER_CORROBORATING:
            corroborating.append(name)
        elif sd.tier == TIER_TRUST:
            trust.append(name)

    breakdown.fired = strong + corroborating
    breakdown.trust_fired = trust
    breakdown.strong_total = sum(SIGNAL_REGISTRY[s].weight for s in strong)
    breakdown.corroborating_raw = sum(SIGNAL_REGISTRY[s].weight for s in corroborating)

    compounded, bonus = compound_score(corroborating)
    breakdown.corroborating_compounded = compounded
    breakdown.compounding_bonus = bonus

    breakdown.trust_adjustments = sum(SIGNAL_REGISTRY[s].weight for s in trust)

    raw = breakdown.strong_total + breakdown.corroborating_compounded + breakdown.trust_adjustments
    breakdown.final_clamped = max(0, min(100, raw))
    return breakdown


# ── Top-level compute (for tests + non-engine callers) ────────────────────────

def compute(signal_names: list[str]) -> int:
    """
    Returns a score 0-100. Short-circuits to 100 on any hard disqualifier.
    Kept as a thin convenience wrapper — the engine uses compute_breakdown().
    """
    for name in signal_names:
        if is_hard_disqualifier(name):
            return 100
    return compute_breakdown(signal_names).final_clamped


# ── Recommendation from score alone (legacy convenience) ──────────────────────
# Kept for report/health endpoints that don't need confidence gating. NOT used
# by the engine — the engine uses derive_recommendation() with confidence.

def recommendation(score: int) -> Recommendation:
    if score >= 70:
        return Recommendation.BLOCK
    if score >= 50:
        return Recommendation.ALLOW_WITH_FLAG
    return Recommendation.ALLOW
