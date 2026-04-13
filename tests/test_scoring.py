"""
Scoring engine tests.

Verifies that signal combinations produce expected risk scores and
recommendations, and that the score is capped at 100.
"""

import pytest

from app.detection import scorer
from app.models.check import Recommendation, RiskLevel


def test_no_signals_is_clean() -> None:
    assert scorer.compute([]) == 0
    assert scorer.risk_level(0) == RiskLevel.LOW
    assert scorer.recommendation(0) == Recommendation.ALLOW


def test_invalid_syntax_is_max() -> None:
    score = scorer.compute(["invalid_syntax"])
    assert score == 100
    assert scorer.recommendation(100) == Recommendation.BLOCK


def test_known_disposable_domain() -> None:
    score = scorer.compute(["known_disposable_domain"])
    assert score == 80
    assert scorer.risk_level(score) == RiskLevel.CRITICAL
    assert scorer.recommendation(score) == Recommendation.BLOCK


def test_no_mx_records() -> None:
    score = scorer.compute(["no_mx_records"])
    assert score == 60
    assert scorer.recommendation(score) == Recommendation.BLOCK


def test_new_domain_alone_is_review() -> None:
    score = scorer.compute(["new_domain_30d"])
    assert score == 40
    assert scorer.recommendation(score) == Recommendation.REVIEW


def test_new_domain_with_suspicious_mx_is_block() -> None:
    score = scorer.compute(["new_domain_30d", "suspicious_mx_infrastructure"])
    assert score == 75
    assert scorer.recommendation(score) == Recommendation.BLOCK


def test_score_caps_at_100() -> None:
    # Even with many signals, score never exceeds 100
    many_signals = [
        "known_disposable_domain",
        "no_mx_records",
        "new_domain_30d",
        "suspicious_mx_infrastructure",
        "catch_all_domain",
        "abuse_pattern_detected",
    ]
    score = scorer.compute(many_signals)
    assert score == 100


def test_role_based_alone_is_medium() -> None:
    score = scorer.compute(["role_based_address"])
    assert score == 20
    assert scorer.recommendation(score) == Recommendation.ALLOW


def test_risk_level_thresholds() -> None:
    assert scorer.risk_level(0) == RiskLevel.LOW
    assert scorer.risk_level(24) == RiskLevel.LOW
    assert scorer.risk_level(25) == RiskLevel.MEDIUM
    assert scorer.risk_level(49) == RiskLevel.MEDIUM
    assert scorer.risk_level(50) == RiskLevel.HIGH
    assert scorer.risk_level(79) == RiskLevel.HIGH
    assert scorer.risk_level(80) == RiskLevel.CRITICAL
    assert scorer.risk_level(100) == RiskLevel.CRITICAL
