from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Recommendation(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class CheckRequest(BaseModel):
    email: str = Field(..., max_length=254, description="Email address to check")


class CheckResponse(BaseModel):
    email: str
    valid_syntax: bool
    disposable: bool
    risk_score: int = Field(ge=0, le=100, description="0 = clean, 100 = certain disposable")
    risk_level: RiskLevel
    catch_all: Optional[bool] = Field(
        None, description="None means not yet probed (Pro tier feature)"
    )
    domain_age_days: Optional[int] = Field(None, description="Days since domain registration")
    mx_shared_with_known_disposables: bool = False
    signals: list[str] = Field(
        default_factory=list,
        description="Machine-readable reasons why this email was flagged",
    )
    recommendation: Recommendation
    cached: bool = Field(False, description="True if result was served from cache")
    latency_ms: int = Field(description="Total processing time in milliseconds")


class ReportRequest(BaseModel):
    domain: str = Field(..., max_length=255)
    outcome: str = Field(
        ...,
        description="confirmed_throwaway | confirmed_legitimate | suspected_throwaway",
        pattern="^(confirmed_throwaway|confirmed_legitimate|suspected_throwaway)$",
    )
    notes: Optional[str] = Field(None, max_length=500)


class ReportResponse(BaseModel):
    accepted: bool
    message: str
