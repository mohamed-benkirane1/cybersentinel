"""Combine deterministic and statistical signals for analyst prioritization.

The risk score is a heuristic priority score, not a probability. Confidence
describes agreement between signal families, not calibrated statistical
confidence. The ML anomaly score is relative to the fitted Isolation Forest.
"""

from dataclasses import dataclass

from sklearn.ensemble import IsolationForest

from app.detection import RuleMatch, evaluate_rules
from app.features import AuthEventFeatures
from app.ml import AnomalyPrediction, predict_anomalies


@dataclass(frozen=True)
class RiskAssessment:
    """An explainable heuristic assessment for one feature record."""

    feature_record: AuthEventFeatures
    risk_score: int
    risk_level: str
    confidence: str
    reasons: tuple[str, ...]
    rule_matches: tuple[RuleMatch, ...]
    ml_anomaly_score: float
    ml_is_anomaly: bool


def assess_risk(
    feature_record: AuthEventFeatures,
    prediction: AnomalyPrediction,
) -> RiskAssessment:
    """Combine rules and one aligned anomaly prediction."""
    if prediction.feature_record is not feature_record:
        raise ValueError("prediction must reference the same feature record")

    rule_matches = tuple(evaluate_rules(feature_record))
    risk_score = min(
        100,
        sum(
            40 for match in rule_matches if match.rule_id in {"R001", "R002"}
        )
        + (20 if prediction.is_anomaly else 0),
    )

    if risk_score < 40:
        risk_level = "low"
    elif risk_score < 60:
        risk_level = "medium"
    else:
        risk_level = "high"

    has_rules = bool(rule_matches)
    if has_rules and prediction.is_anomaly:
        confidence = "high"
    elif has_rules or prediction.is_anomaly:
        confidence = "medium"
    else:
        confidence = "low"

    reasons: list[str] = []
    for match in rule_matches:
        if match.rule_id == "R001":
            reasons.append(
                f"{feature_record.failed_attempts_5m} failed authentication "
                "attempts within 5 minutes"
            )
        elif match.rule_id == "R002":
            reasons.append(
                f"{feature_record.unique_users_per_ip_5m} distinct users observed "
                "from the same source IP within 5 minutes"
            )
    if prediction.is_anomaly:
        reasons.append(
            "Behavior marked as statistically atypical by Isolation Forest."
        )

    return RiskAssessment(
        feature_record=feature_record,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        reasons=tuple(reasons),
        rule_matches=rule_matches,
        ml_anomaly_score=float(prediction.anomaly_score),
        ml_is_anomaly=bool(prediction.is_anomaly),
    )


def assess_risk_batch(
    feature_records: list[AuthEventFeatures],
    predictions: list[AnomalyPrediction],
) -> list[RiskAssessment]:
    """Assess aligned feature records and predictions in input order."""
    if len(feature_records) != len(predictions):
        raise ValueError("feature_records and predictions must have the same length")

    return [
        assess_risk(feature_record, prediction)
        for feature_record, prediction in zip(
            feature_records,
            predictions,
            strict=True,
        )
    ]


def analyze_with_model(
    model: IsolationForest,
    feature_records: list[AuthEventFeatures],
) -> list[RiskAssessment]:
    """Predict anomaly signals and assess risk without training the model."""
    predictions = predict_anomalies(model, feature_records)
    return assess_risk_batch(feature_records, predictions)
