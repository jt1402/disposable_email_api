"""
CheckResponse — the public API contract.

Five-block structure per technical blueprint §19:
  meta    — request context + model state
  verdict — the answer in plain English
  score   — numbers, confidence, thresholds
  signals — every signal fired, with direction/weight/description
  checks  — every check run, with duration and status
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ── Enums ─────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Recommendation(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_FLAG = "allow_with_flag"
    VERIFY_MANUALLY = "verify_manually"
    BLOCK = "block"


class RiskProfile(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class ModelPhase(str, Enum):
    BOOTSTRAP = "bootstrap"
    CALIBRATED = "calibrated"
    OPTIMISED = "optimised"


class SignalDirection(str, Enum):
    RISK = "risk"
    TRUST = "trust"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ── Request models ────────────────────────────────────────────────────────────

class CheckRequest(BaseModel):
    email: str = Field(..., max_length=254, description="Email address to check")


# ── Meta block ────────────────────────────────────────────────────────────────

class Meta(BaseModel):
    request_id: str = Field(description="Unique request ID — include in support tickets")
    email: str
    domain: str
    checked_at: str = Field(description="ISO-8601 UTC timestamp")
    latency_ms: int
    api_version: str = "2026-04"
    model_phase: ModelPhase
    model_version: str
    path_taken: str = Field(description="fast | standard | deep | async")
    cached: bool
    cache_age_seconds: int | None = None


# ── Verdict block ─────────────────────────────────────────────────────────────

class Verdict(BaseModel):
    recommendation: Recommendation
    risk_level: RiskLevel
    disposable: bool
    catch_all: bool | None = Field(
        None, description="None = not probed (tier-gated or disabled)"
    )
    valid_address: bool
    safe_to_send: bool
    summary: str = Field(description="One plain-English sentence explaining the verdict")
    degraded_mode: bool = False
    degraded_reason: str | None = None


# ── Score block ───────────────────────────────────────────────────────────────

class ScoreComponents(BaseModel):
    strong_signals: int = 0
    corroborating: int = 0
    trust_adjustments: int = 0
    compounding_bonus: int = 0
    final_clamped: int = 0


class Thresholds(BaseModel):
    block_at: int
    flag_at: int
    your_profile: RiskProfile


class CatchAllDetail(BaseModel):
    detected: bool
    probability: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    legitimate_use_likely: bool
    type: str = Field(description="confirmed | suspected | cleared")


class Score(BaseModel):
    value: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel
    components: ScoreComponents
    thresholds: Thresholds
    catch_all_detail: CatchAllDetail | None = None


# ── Signals block ─────────────────────────────────────────────────────────────

class Signal(BaseModel):
    name: str
    category: str = Field(description="syntax | blocklist | domain_infrastructure | smtp_analysis | behavioral")
    direction: SignalDirection
    weight: int = Field(description="Positive = risk, negative = trust")
    description: str
    value: Any | None = None
    unit: str | None = None
    probe_result: dict | None = None
    extra: dict = Field(default_factory=dict)


class Compounding(BaseModel):
    applied: bool
    signal_count: int
    bonus_applied: int
    explanation: str = ""


class SuppressedSignal(BaseModel):
    name: str
    reason: str = ""


class Signals(BaseModel):
    fired: list[Signal] = Field(default_factory=list)
    trust_signals: list[Signal] = Field(default_factory=list)
    suppressed: list[SuppressedSignal] = Field(default_factory=list)
    compounding: Compounding


# ── Checks block ──────────────────────────────────────────────────────────────

class Check(BaseModel):
    name: str
    status: str = Field(description="passed | checked | completed | failed | skipped")
    duration_ms: float
    result: str | None = None
    probe_detail: dict | None = None


class Checks(BaseModel):
    run: list[Check] = Field(default_factory=list)
    skipped: list[Check] = Field(default_factory=list)
    failed: list[Check] = Field(default_factory=list)
    path_explanation: str = ""


# ── Full response ─────────────────────────────────────────────────────────────

class CheckResponse(BaseModel):
    meta: Meta
    verdict: Verdict
    score: Score
    signals: Signals
    checks: Checks


# ── Report endpoint ───────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    domain: str = Field(..., max_length=255)
    outcome: str = Field(
        ...,
        description="confirmed_throwaway | confirmed_legitimate | suspected_throwaway",
        pattern="^(confirmed_throwaway|confirmed_legitimate|suspected_throwaway)$",
    )
    notes: str | None = Field(None, max_length=500)


class ReportResponse(BaseModel):
    accepted: bool
    message: str
