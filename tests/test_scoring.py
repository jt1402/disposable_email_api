"""
Scoring engine tests.

Covers:
- Hard disqualifiers short-circuit to 100
- Compounding math (1.3x / 1.6x / 1.9x)
- Trust signals reduce score
- Confidence gate produces verify_manually on high-score/low-confidence
- Named compound catch_all_new_domain replaces its parts
- Per-profile thresholds (strict/balanced/permissive)
- Bootstrap vs calibrated phase thresholds
- Summary generator produces human-readable output
"""

import pytest

from app.detection import scorer
from app.models.check import (
    ModelPhase,
    Recommendation,
    RiskLevel,
    RiskProfile,
)

# ── Basic compute() — hard disqualifiers + clean ─────────────────────────────

def test_no_signals_is_clean() -> None:
    assert scorer.compute([]) == 0
    assert scorer.risk_level(0) == RiskLevel.LOW


def test_invalid_syntax_is_hard_disqualifier() -> None:
    assert scorer.compute(["invalid_syntax"]) == 100
    assert scorer.is_hard_disqualifier("invalid_syntax")


def test_no_mx_records_is_hard_disqualifier() -> None:
    assert scorer.compute(["no_mx_records"]) == 100


def test_known_disposable_high_confidence_is_hard_disqualifier() -> None:
    assert scorer.compute(["known_disposable_domain_high_confidence"]) == 100


def test_domain_does_not_exist_is_hard_disqualifier() -> None:
    assert scorer.compute(["domain_does_not_exist"]) == 100


# ── Compounding math ──────────────────────────────────────────────────────────

def test_single_corroborating_no_compounding() -> None:
    compounded, bonus = scorer.compound_score(["privacy_whois"])  # unknown → dropped
    assert compounded == 0 and bonus == 0

    compounded, bonus = scorer.compound_score(["role_based_address"])
    assert compounded == 12
    assert bonus == 0


def test_two_corroborating_signals_compound() -> None:
    # new_domain_30d=25, no_spf_record=10 → sorted desc: [25, 10]
    # score = 25 + 10 * 1.3 = 38
    compounded, bonus = scorer.compound_score(["new_domain_30d", "no_spf_record"])
    assert compounded == 38
    assert bonus == 3  # 38 - (25+10)


def test_four_corroborating_signals_compound_to_near_cap() -> None:
    signals = [
        "new_domain_30d",        # 25
        "suspicious_mx_infrastructure",  # 30
        "no_spf_record",         # 10
        "role_based_address",    # 12
    ]
    # sorted: [30, 25, 12, 10]
    # score = 30 + 25*1.3 + 12*1.6 + 10*1.9 = 30 + 32.5 + 19.2 + 19 = 100.7 → capped 95
    compounded, bonus = scorer.compound_score(signals)
    assert compounded == 95
    face = 30 + 25 + 12 + 10
    assert bonus == 95 - face


def test_compound_score_caps_at_95_not_100() -> None:
    signals = ["suspicious_mx_infrastructure", "catch_all_domain",
               "abuse_pattern_detected", "new_domain_30d", "no_spf_record"]
    compounded, _ = scorer.compound_score(signals)
    assert compounded == 95  # hard cap — leaves room for trust signals


# ── Trust signals reduce score ────────────────────────────────────────────────

def test_trust_signals_reduce_catch_all_score() -> None:
    # Fraud-side: catch_all_domain (corroborating 30) + new_domain_30d (25)
    # → gets promoted to catch_all_new_domain in the engine, but at the
    # compute_breakdown() level if we don't promote:
    fraud_signals = ["catch_all_domain", "new_domain_30d", "suspicious_mx_infrastructure"]
    fraud = scorer.compute_breakdown(fraud_signals)

    # Legit-side: same catch_all, but with old+authenticated domain
    legit_signals = ["catch_all_domain", "domain_age_over_5_years",
                     "spf_dkim_dmarc_all_present", "mx_known_legitimate_host",
                     "catch_all_old_established"]
    legit = scorer.compute_breakdown(legit_signals)

    assert fraud.final_clamped > 40, "Fraud pattern should score high"
    assert legit.final_clamped < 20, f"Legit old-domain catch-all should score LOW, got {legit.final_clamped}"


def test_trusted_provider_zeroes_out_score() -> None:
    # gmail.com etc. → known_legitimate_provider (-30)
    b = scorer.compute_breakdown(["known_legitimate_provider"])
    assert b.final_clamped == 0  # clamp floor
    assert b.trust_adjustments == -30


def test_strong_signal_weights() -> None:
    b = scorer.compute_breakdown(["catch_all_new_domain"])
    assert b.final_clamped == 85
    assert b.strong_total == 85


# ── Confidence calculation ────────────────────────────────────────────────────

def test_confidence_starts_at_1() -> None:
    assert scorer.calculate_confidence([]) == 1.0


def test_confidence_penalties_apply() -> None:
    c = scorer.calculate_confidence(["smtp_probe_timeout", "whois_lookup_failed"])
    assert c == pytest.approx(1.0 - 0.15 - 0.10)


def test_confidence_has_floor() -> None:
    c = scorer.calculate_confidence(["smtp_probe_timeout"] * 20)
    assert c == 0.30


def test_confidence_level_bands() -> None:
    from app.models.check import ConfidenceLevel
    assert scorer.confidence_level(0.95) == ConfidenceLevel.HIGH
    assert scorer.confidence_level(0.80) == ConfidenceLevel.HIGH
    assert scorer.confidence_level(0.70) == ConfidenceLevel.MEDIUM
    assert scorer.confidence_level(0.55) == ConfidenceLevel.MEDIUM
    assert scorer.confidence_level(0.45) == ConfidenceLevel.LOW


# ── Confidence gate → verify_manually ────────────────────────────────────────

def test_high_score_high_confidence_blocks() -> None:
    th = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    rec = scorer.derive_recommendation(85, 0.95, ["catch_all_new_domain"], th)
    assert rec == Recommendation.BLOCK


def test_high_score_low_confidence_verifies_manually() -> None:
    """The single rule that prevents most false positives."""
    th = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    rec = scorer.derive_recommendation(85, 0.45, ["catch_all_new_domain"], th)
    assert rec == Recommendation.VERIFY_MANUALLY


def test_medium_score_flags() -> None:
    th = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    rec = scorer.derive_recommendation(55, 0.90, ["new_domain_30d", "no_spf_record"], th)
    assert rec == Recommendation.ALLOW_WITH_FLAG


def test_low_score_with_catch_all_still_flags() -> None:
    th = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    rec = scorer.derive_recommendation(15, 0.95, ["catch_all_domain"], th)
    assert rec == Recommendation.ALLOW_WITH_FLAG


def test_clean_email_allows() -> None:
    th = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    assert scorer.derive_recommendation(0, 1.0, [], th) == Recommendation.ALLOW


# ── Profile differences ──────────────────────────────────────────────────────

def test_strict_profile_blocks_earlier() -> None:
    strict = scorer.thresholds_for(RiskProfile.STRICT, ModelPhase.CALIBRATED)
    balanced = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    permissive = scorer.thresholds_for(RiskProfile.PERMISSIVE, ModelPhase.CALIBRATED)
    assert strict.block < balanced.block < permissive.block


def test_strict_blocks_score_that_balanced_only_flags() -> None:
    strict = scorer.thresholds_for(RiskProfile.STRICT, ModelPhase.CALIBRATED)
    balanced = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)

    score, conf = 60, 0.95
    assert scorer.derive_recommendation(score, conf, [], strict) == Recommendation.BLOCK
    assert scorer.derive_recommendation(score, conf, [], balanced) == Recommendation.ALLOW_WITH_FLAG


# ── Bootstrap vs calibrated phase ────────────────────────────────────────────

def test_bootstrap_thresholds_are_stricter() -> None:
    boot = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.BOOTSTRAP)
    cal = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.CALIBRATED)
    assert boot.block > cal.block
    assert boot.flag > cal.flag
    assert boot.confidence_gate > cal.confidence_gate


def test_bootstrap_requires_higher_score_to_block() -> None:
    boot = scorer.thresholds_for(RiskProfile.BALANCED, ModelPhase.BOOTSTRAP)
    # Score 75, high conf → in calibrated this blocks, in bootstrap it flags
    rec = scorer.derive_recommendation(75, 0.90, [], boot)
    assert rec == Recommendation.ALLOW_WITH_FLAG


# ── Summary generator ───────────────────────────────────────────────────────

def test_summary_for_clean() -> None:
    s = scorer.build_summary([], [], 0, Recommendation.ALLOW)
    assert "legitimate" in s.lower() or "no risk" in s.lower()


def test_summary_for_invalid_syntax() -> None:
    s = scorer.build_summary(["invalid_syntax"], [], 100, Recommendation.BLOCK)
    assert "syntax" in s.lower()


def test_summary_for_fraud_pattern() -> None:
    s = scorer.build_summary(
        ["catch_all_new_domain", "suspicious_mx_infrastructure"],
        [],
        95,
        Recommendation.BLOCK,
        domain_age_days=14,
        catch_all=True,
    )
    assert "14" in s
    assert "catch-all" in s.lower()


def test_summary_for_verify_manually() -> None:
    s = scorer.build_summary(
        ["catch_all_domain"], [], 85, Recommendation.VERIFY_MANUALLY,
        catch_all=True,
    )
    assert "review" in s.lower() or "verify" in s.lower() or "manual" in s.lower()


# ── Risk level bands (unchanged) ─────────────────────────────────────────────

def test_risk_level_thresholds() -> None:
    assert scorer.risk_level(0) == RiskLevel.LOW
    assert scorer.risk_level(24) == RiskLevel.LOW
    assert scorer.risk_level(25) == RiskLevel.MEDIUM
    assert scorer.risk_level(49) == RiskLevel.MEDIUM
    assert scorer.risk_level(50) == RiskLevel.HIGH
    assert scorer.risk_level(79) == RiskLevel.HIGH
    assert scorer.risk_level(80) == RiskLevel.CRITICAL
    assert scorer.risk_level(100) == RiskLevel.CRITICAL


# ── Full breakdown integration ───────────────────────────────────────────────

def test_breakdown_components_add_up() -> None:
    b = scorer.compute_breakdown([
        "cross_customer_abuse_pattern",  # strong, 35
        "new_domain_30d",                # corroborating, 25
        "no_spf_record",                 # corroborating, 10
        "domain_age_over_5_years",       # trust, -25
    ])
    # strong_total = 35
    # corroborating: [25, 10] compounded = 25 + 10*1.3 = 38
    # trust = -25
    # sum = 35 + 38 - 25 = 48
    assert b.strong_total == 35
    assert b.corroborating_compounded == 38
    assert b.trust_adjustments == -25
    assert b.final_clamped == 48


def test_floor_at_zero_when_trust_outweighs_risk() -> None:
    b = scorer.compute_breakdown([
        "role_based_address",           # corroborating, 12
        "known_legitimate_provider",    # trust, -30
    ])
    assert b.final_clamped == 0  # clamp floor
