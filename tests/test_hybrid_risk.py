from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.ml import AnomalyPrediction, train_isolation_forest
from app.models import AuthenticationEvent
from app.risk import (
    RiskAssessment,
    analyze_with_model,
    assess_risk,
    assess_risk_batch,
)


START_TIME = datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)


def make_feature_record(
    *,
    index: int = 0,
    failed_attempts_5m: int = 0,
    unique_users_per_ip_5m: int = 1,
) -> AuthEventFeatures:
    event = AuthenticationEvent(
        timestamp=START_TIME + timedelta(seconds=index),
        user_id=f"user-{index}",
        source_ip=f"192.0.2.{index + 1}",
        result="failure" if failed_attempts_5m else "success",
        service="vpn",
    )
    return AuthEventFeatures(
        event=event,
        attempts_5m=max(1, failed_attempts_5m),
        failed_attempts_5m=failed_attempts_5m,
        unique_users_per_ip_5m=unique_users_per_ip_5m,
        unique_ips_per_user_30m=1,
    )


def make_prediction(
    feature_record: AuthEventFeatures,
    *,
    anomaly_score: float = 0.0,
    is_anomaly: bool = False,
) -> AnomalyPrediction:
    return AnomalyPrediction(
        feature_record=feature_record,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
    )


def normal_training_records() -> list[AuthEventFeatures]:
    return compute_auth_features(generate_normal_events(80, seed=123))


def test_risk_assessment_is_immutable() -> None:
    feature_record = make_feature_record()
    assessment = assess_risk(feature_record, make_prediction(feature_record))

    with pytest.raises(FrozenInstanceError):
        assessment.risk_score = 20


def test_no_signal_produces_low_zero_assessment() -> None:
    feature_record = make_feature_record()

    assessment = assess_risk(feature_record, make_prediction(feature_record))

    assert assessment.risk_score == 0
    assert assessment.risk_level == "low"
    assert assessment.confidence == "low"
    assert assessment.reasons == ()


def test_r001_only_produces_medium_assessment() -> None:
    feature_record = make_feature_record(failed_attempts_5m=5)

    assessment = assess_risk(feature_record, make_prediction(feature_record))

    assert assessment.risk_score == 40
    assert assessment.risk_level == "medium"
    assert assessment.confidence == "medium"


def test_r002_only_produces_medium_assessment() -> None:
    feature_record = make_feature_record(unique_users_per_ip_5m=4)

    assessment = assess_risk(feature_record, make_prediction(feature_record))

    assert assessment.risk_score == 40
    assert assessment.risk_level == "medium"
    assert assessment.confidence == "medium"


def test_ml_only_produces_low_score_with_medium_confidence() -> None:
    feature_record = make_feature_record()

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=True),
    )

    assert assessment.risk_score == 20
    assert assessment.risk_level == "low"
    assert assessment.confidence == "medium"


def test_r001_and_ml_produce_high_assessment() -> None:
    feature_record = make_feature_record(failed_attempts_5m=5)

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=True),
    )

    assert assessment.risk_score == 60
    assert assessment.risk_level == "high"
    assert assessment.confidence == "high"


def test_r002_and_ml_produce_high_assessment() -> None:
    feature_record = make_feature_record(unique_users_per_ip_5m=4)

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=True),
    )

    assert assessment.risk_score == 60
    assert assessment.risk_level == "high"
    assert assessment.confidence == "high"


def test_both_rules_without_ml_produce_high_score_medium_confidence() -> None:
    feature_record = make_feature_record(
        failed_attempts_5m=5,
        unique_users_per_ip_5m=4,
    )

    assessment = assess_risk(feature_record, make_prediction(feature_record))

    assert assessment.risk_score == 80
    assert assessment.risk_level == "high"
    assert assessment.confidence == "medium"


def test_both_rules_and_ml_produce_maximum_high_assessment() -> None:
    feature_record = make_feature_record(
        failed_attempts_5m=5,
        unique_users_per_ip_5m=4,
    )

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=True),
    )

    assert assessment.risk_score == 100
    assert assessment.risk_level == "high"
    assert assessment.confidence == "high"


def test_risk_score_never_exceeds_one_hundred() -> None:
    feature_record = make_feature_record(
        failed_attempts_5m=100,
        unique_users_per_ip_5m=100,
    )

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, anomaly_score=1000.0, is_anomaly=True),
    )

    assert assessment.risk_score == 100


def test_anomaly_score_magnitude_does_not_change_risk_score() -> None:
    feature_record = make_feature_record()

    low_magnitude = assess_risk(
        feature_record,
        make_prediction(feature_record, anomaly_score=0.01, is_anomaly=True),
    )
    high_magnitude = assess_risk(
        feature_record,
        make_prediction(feature_record, anomaly_score=1000.0, is_anomaly=True),
    )

    assert low_magnitude.risk_score == high_magnitude.risk_score == 20


def test_rule_matches_are_ordered_r001_then_r002() -> None:
    feature_record = make_feature_record(
        failed_attempts_5m=5,
        unique_users_per_ip_5m=4,
    )

    assessment = assess_risk(feature_record, make_prediction(feature_record))

    assert [match.rule_id for match in assessment.rule_matches] == ["R001", "R002"]


def test_reasons_are_ordered_r001_then_r002_then_ml() -> None:
    feature_record = make_feature_record(
        failed_attempts_5m=6,
        unique_users_per_ip_5m=4,
    )

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=True),
    )

    assert assessment.reasons == (
        "6 failed authentication attempts within 5 minutes",
        "4 distinct users observed from the same source IP within 5 minutes",
        "Behavior marked as statistically atypical by Isolation Forest.",
    )


def test_ml_anomaly_score_is_preserved_as_float() -> None:
    feature_record = make_feature_record()

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, anomaly_score=0.123456),
    )

    assert assessment.ml_anomaly_score == 0.123456
    assert type(assessment.ml_anomaly_score) is float


@pytest.mark.parametrize("is_anomaly", [False, True])
def test_ml_is_anomaly_is_preserved(is_anomaly: bool) -> None:
    feature_record = make_feature_record()

    assessment = assess_risk(
        feature_record,
        make_prediction(feature_record, is_anomaly=is_anomaly),
    )

    assert assessment.ml_is_anomaly is is_anomaly


def test_assess_risk_rejects_misaligned_prediction() -> None:
    with pytest.raises(ValueError):
        assess_risk(make_feature_record(), make_prediction(make_feature_record()))


def test_assess_risk_batch_returns_empty_list_for_empty_input() -> None:
    assert assess_risk_batch([], []) == []


def test_assess_risk_batch_rejects_different_lengths() -> None:
    with pytest.raises(ValueError):
        assess_risk_batch([make_feature_record()], [])


def test_assess_risk_batch_rejects_misaligned_prediction() -> None:
    with pytest.raises(ValueError):
        assess_risk_batch(
            [make_feature_record()],
            [make_prediction(make_feature_record())],
        )


def test_assess_risk_batch_preserves_order() -> None:
    feature_records = [make_feature_record(index=index) for index in range(3)]
    predictions = [make_prediction(record) for record in feature_records]

    assessments = assess_risk_batch(feature_records, predictions)

    assert [assessment.feature_record for assessment in assessments] == feature_records


def test_analyze_with_model_returns_assessment_per_feature_record() -> None:
    model = train_isolation_forest(normal_training_records())
    feature_records = compute_auth_features(generate_normal_events(10, seed=999))

    assessments = analyze_with_model(model, feature_records)

    assert len(assessments) == len(feature_records)
    assert [assessment.feature_record for assessment in assessments] == feature_records


def test_failure_burst_last_event_contains_r001_match() -> None:
    model = train_isolation_forest(normal_training_records())
    feature_records = compute_auth_features(
        generate_failure_burst(attempts=6, start_time=START_TIME)
    )

    assessments = analyze_with_model(model, feature_records)

    assert "R001" in {
        match.rule_id for match in assessments[-1].rule_matches
    }


def test_multi_account_last_event_contains_r002_match() -> None:
    model = train_isolation_forest(normal_training_records())
    feature_records = compute_auth_features(
        generate_multi_account_activity(
            user_ids=["user-a", "user-b", "user-c", "user-d"],
            start_time=START_TIME,
        )
    )

    assessments = analyze_with_model(model, feature_records)

    assert "R002" in {
        match.rule_id for match in assessments[-1].rule_matches
    }
