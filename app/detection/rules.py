"""Deterministic rules for authentication event features."""

from dataclasses import dataclass
from datetime import datetime

from app.features import AuthEventFeatures


@dataclass(frozen=True)
class RuleMatch:
    """A deterministic rule triggered by one authentication event."""

    rule_id: str
    severity: str
    description: str
    evidence: dict[str, object]
    timestamp: datetime


def evaluate_r001(
    features: AuthEventFeatures,
    *,
    threshold: int = 5,
) -> RuleMatch | None:
    """Detect a high failed authentication attempt count."""
    if threshold <= 0:
        raise ValueError("threshold must be greater than zero")
    if features.failed_attempts_5m < threshold:
        return None

    return RuleMatch(
        rule_id="R001",
        severity="high",
        description="High failed authentication attempt count within five minutes.",
        evidence={
            "user_id": features.event.user_id,
            "failed_attempts_5m": features.failed_attempts_5m,
            "threshold": threshold,
        },
        timestamp=features.event.timestamp,
    )


def evaluate_r002(
    features: AuthEventFeatures,
    *,
    threshold: int = 4,
) -> RuleMatch | None:
    """Detect one source targeting multiple accounts."""
    if threshold <= 0:
        raise ValueError("threshold must be greater than zero")
    if features.unique_users_per_ip_5m < threshold:
        return None

    return RuleMatch(
        rule_id="R002",
        severity="high",
        description="One source observed across multiple accounts within five minutes.",
        evidence={
            "source_ip": str(features.event.source_ip),
            "unique_users_per_ip_5m": features.unique_users_per_ip_5m,
            "threshold": threshold,
        },
        timestamp=features.event.timestamp,
    )


def evaluate_rules(features: AuthEventFeatures) -> list[RuleMatch]:
    """Return triggered rules in deterministic rule order."""
    matches: list[RuleMatch] = []
    for match in (evaluate_r001(features), evaluate_r002(features)):
        if match is not None:
            matches.append(match)
    return matches


def evaluate_feature_batch(
    feature_records: list[AuthEventFeatures],
) -> list[RuleMatch]:
    """Evaluate feature records in their supplied order."""
    matches: list[RuleMatch] = []
    for features in feature_records:
        matches.extend(evaluate_rules(features))
    return matches
