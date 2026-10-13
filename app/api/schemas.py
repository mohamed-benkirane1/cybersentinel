"""Request and response schemas for the CyberSentinel API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import AuthenticationEvent


class AnalyzeRequest(BaseModel):
    """A non-empty batch of authentication events to analyze."""

    model_config = ConfigDict(extra="forbid")

    events: list[AuthenticationEvent] = Field(min_length=1)


class HealthResponse(BaseModel):
    """Service health and prototype status."""

    status: str
    service: str
    model_ready: bool
    prototype: bool


class RuleMatchResponse(BaseModel):
    """Serializable deterministic rule match."""

    rule_id: str
    severity: str
    description: str
    evidence: dict[str, object]
    timestamp: datetime


class RiskAssessmentResponse(BaseModel):
    """Serializable hybrid assessment for one authentication event."""

    timestamp: datetime
    user_id: str
    source_ip: str
    result: str
    service: str
    attempts_5m: int
    failed_attempts_5m: int
    unique_users_per_ip_5m: int
    unique_ips_per_user_30m: int
    risk_score: int
    risk_level: str
    confidence: str
    reasons: list[str]
    rule_matches: list[RuleMatchResponse]
    ml_anomaly_score: float
    ml_is_anomaly: bool


class AnalyzeResponse(BaseModel):
    """Ordered assessments returned for an analyzed batch."""

    assessment_count: int
    assessments: list[RiskAssessmentResponse]
