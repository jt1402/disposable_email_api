"""
Scoring Engine — aggregates signals from all layers into a single risk score.

Score is deterministic and explainable: each signal contributes a fixed amount.
Customers can tune their own block threshold (default: block at score >= 50).
"""

from app.models.check import Recommendation, RiskLevel

# ── Signal weights ────────────────────────────────────────────────────────────
# Ordered by severity. Score is additive, capped at 100.
SIGNAL_WEIGHTS: dict[str, int] = {
    # Layer 1 — syntax
    "invalid_syntax": 100,        # Immediate: not a valid email
    "unicode_homograph_domain": 70,
    "non_ascii_domain": 15,
    "non_standard_local": 10,
    "role_based_address": 20,

    # Layer 2 — blocklist
    "known_disposable_domain": 80,

    # Layer 3 — DNS
    "no_mx_records": 60,          # Domain cannot receive email
    "suspicious_mx_infrastructure": 35,
    "new_domain_30d": 40,
    "new_domain_90d": 20,
    "domain_age_unknown": 10,

    # Layer 4 — behavioral
    "abuse_pattern_detected": 25,
    "cross_customer_abuse_pattern": 20,

    # Layer 5 — catch-all
    "catch_all_domain": 30,
}

# ── Risk level thresholds ─────────────────────────────────────────────────────
def risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def recommendation(score: int) -> Recommendation:
    if score >= 50:
        return Recommendation.BLOCK
    if score >= 25:
        return Recommendation.REVIEW
    return Recommendation.ALLOW


def compute(signals: list[str]) -> int:
    """
    Returns a risk score 0–100.
    invalid_syntax immediately returns 100 without accumulating other signals.
    """
    if "invalid_syntax" in signals:
        return 100

    total = sum(SIGNAL_WEIGHTS.get(s, 0) for s in signals)
    return min(100, total)
