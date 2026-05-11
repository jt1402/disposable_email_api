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
    # Three outcomes — see scorer.derive_recommendation.
    # allow_with_flag is the safety-margin verdict; the customer routes
    # flagged users through their verification / friction step.
    ALLOW = "allow"
    ALLOW_WITH_FLAG = "allow_with_flag"
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


class DomainCheckRequest(BaseModel):
    domain: str = Field(..., max_length=255, description="Domain to check (no local part)")


class BulkCheckRequest(BaseModel):
    emails: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Email addresses to check (1–100 per request)",
    )


class BulkSummary(BaseModel):
    total: int
    credits_charged: int
    credits_remaining: int
    elapsed_ms: int


class BulkCheckResponse(BaseModel):
    items: list["CheckResponse"]
    summary: BulkSummary


class AsyncCheckRequest(BaseModel):
    email: str = Field(..., max_length=254)
    webhook_url: str = Field(
        ...,
        max_length=2048,
        description="HTTPS URL to POST the final verdict to. Must be public (no private IPs).",
    )
    webhook_secret: str | None = Field(
        None,
        max_length=128,
        description="Optional shared secret. If set, payload is signed with HMAC-SHA256 "
                    "and the digest is sent in the X-VerifyMail-Signature header.",
    )


class AsyncCheckResponse(BaseModel):
    request_id: str
    status: str = Field(description="Always 'pending' — final verdict is delivered via webhook")
    preliminary: "CheckResponse" = Field(
        description="Best-effort verdict from the fast/standard layers. The final "
                    "verdict (delivered via webhook) may differ once SMTP probes complete."
    )
    webhook_url: str
    estimated_completion_ms: int


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
    disposable: bool = Field(
        description="True only when a known-disposable blocklist signal fired. "
                    "False for other hard disqualifiers like no_mx_records."
    )
    catch_all: bool | None = Field(
        None, description="null = not probed (tier-gated or feature disabled). "
                          "Use catch_all_checked to distinguish 'not run' from 'checked, not catch-all'."
    )
    catch_all_checked: bool = Field(
        False, description="True if the SMTP catch-all probe actually ran. "
                           "When false, catch_all is always null — feature is not yet enabled."
    )
    valid_address: bool = Field(
        description="True only if syntax passes AND the domain has MX records. "
                    "Not a pure syntax check — requires the domain to be deliverable."
    )
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
    queued_for_review: bool = Field(
        True, description="Report is queued — does not immediately affect scoring. "
                          "Reports feed the domain_stats feedback loop and are weighted by reporter history."
    )
    review_sla_hours: int = Field(
        4, description="Maximum turnaround time for human review of flagged reports."
    )
    report_id: str = Field("", description="Include in support tickets about this report.")
    message: str


# Resolve forward references now that CheckResponse is defined.
BulkCheckResponse.model_rebuild()
AsyncCheckResponse.model_rebuild()
