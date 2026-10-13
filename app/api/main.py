"""FastAPI entry point for the CyberSentinel prototype."""

from fastapi import FastAPI, HTTPException
from sklearn.ensemble import IsolationForest

from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    RiskAssessmentResponse,
    RuleMatchResponse,
)
from app.data import generate_normal_events
from app.features import compute_auth_features
from app.ml import train_isolation_forest
from app.risk import RiskAssessment, analyze_with_model


def _build_default_model() -> IsolationForest:
    normal_events = generate_normal_events(200, seed=123)
    training_records = compute_auth_features(normal_events)
    return train_isolation_forest(
        training_records,
        contamination="auto",
        random_state=42,
    )


def _to_risk_response(assessment: RiskAssessment) -> RiskAssessmentResponse:
    feature_record = assessment.feature_record
    event = feature_record.event
    return RiskAssessmentResponse(
        timestamp=event.timestamp,
        user_id=event.user_id,
        source_ip=str(event.source_ip),
        result=event.result,
        service=event.service,
        attempts_5m=feature_record.attempts_5m,
        failed_attempts_5m=feature_record.failed_attempts_5m,
        unique_users_per_ip_5m=feature_record.unique_users_per_ip_5m,
        unique_ips_per_user_30m=feature_record.unique_ips_per_user_30m,
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        confidence=assessment.confidence,
        reasons=list(assessment.reasons),
        rule_matches=[
            RuleMatchResponse(
                rule_id=match.rule_id,
                severity=match.severity,
                description=match.description,
                evidence=match.evidence,
                timestamp=match.timestamp,
            )
            for match in assessment.rule_matches
        ],
        ml_anomaly_score=assessment.ml_anomaly_score,
        ml_is_anomaly=assessment.ml_is_anomaly,
    )


def create_app(
    *,
    model: IsolationForest | None = None,
) -> FastAPI:
    api = FastAPI(
        title="CyberSentinel",
        version="0.1.0",
    )
    api.state.model = model if model is not None else _build_default_model()

    @api.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="cybersentinel",
            model_ready=getattr(api.state, "model", None) is not None,
            prototype=True,
        )

    @api.post("/analyze", response_model=AnalyzeResponse)
    def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
        try:
            feature_records = compute_auth_features(request.events)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        assessments = analyze_with_model(api.state.model, feature_records)
        response_assessments = [
            _to_risk_response(assessment) for assessment in assessments
        ]
        return AnalyzeResponse(
            assessment_count=len(response_assessments),
            assessments=response_assessments,
        )

    return api


app = create_app()
