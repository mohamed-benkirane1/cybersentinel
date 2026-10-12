from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from app.data import generate_normal_events
from app.evaluation import (
    EvaluationResult,
    EvaluationSample,
    build_evaluation_samples,
    evaluate_predictions,
    run_synthetic_evaluation,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.ml import AnomalyPrediction
from app.models import AuthenticationEvent


START_TIME = datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc)


def make_feature_record(index: int = 0) -> AuthEventFeatures:
    event = AuthenticationEvent(
        timestamp=START_TIME + timedelta(seconds=index),
        user_id=f"user-{index}",
        source_ip=f"192.0.2.{index + 1}",
        result="success",
        service="vpn",
    )
    return AuthEventFeatures(
        event=event,
        attempts_5m=1,
        failed_attempts_5m=0,
        unique_users_per_ip_5m=1,
        unique_ips_per_user_30m=1,
    )


def metric_case() -> tuple[list[EvaluationSample], list[AnomalyPrediction]]:
    actual_values = [True, False, False, True]
    predicted_values = [True, True, False, False]
    records = [make_feature_record(index) for index in range(4)]
    samples = [
        EvaluationSample(
            feature_record=record,
            is_injected_suspicious=actual,
            scenario="failure_burst" if actual else "normal",
        )
        for record, actual in zip(records, actual_values, strict=True)
    ]
    predictions = [
        AnomalyPrediction(
            feature_record=record,
            anomaly_score=float(index),
            is_anomaly=predicted,
        )
        for index, (record, predicted) in enumerate(
            zip(records, predicted_values, strict=True)
        )
    ]
    return samples, predictions


def normal_training_records() -> list[AuthEventFeatures]:
    return compute_auth_features(generate_normal_events(80, seed=123))


def test_evaluation_sample_is_immutable() -> None:
    sample = EvaluationSample(
        feature_record=make_feature_record(),
        is_injected_suspicious=False,
        scenario="normal",
    )

    with pytest.raises(FrozenInstanceError):
        sample.scenario = "failure_burst"


def test_evaluation_result_is_immutable() -> None:
    result = evaluate_predictions([], [])

    with pytest.raises(FrozenInstanceError):
        result.sample_count = 1


@pytest.mark.parametrize("normal_count", [0, -1])
def test_build_evaluation_samples_rejects_non_positive_normal_count(
    normal_count: int,
) -> None:
    with pytest.raises(ValueError):
        build_evaluation_samples(
            normal_count=normal_count,
            start_time=START_TIME,
        )


def test_build_evaluation_samples_rejects_naive_start_time() -> None:
    with pytest.raises(ValueError):
        build_evaluation_samples(start_time=datetime(2026, 7, 1, 10, 0))


def test_build_evaluation_samples_has_expected_total_count() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert len(samples) == 15


def test_build_evaluation_samples_has_expected_normal_count() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert sum(sample.scenario == "normal" for sample in samples) == 5


def test_build_evaluation_samples_has_six_failure_burst_samples() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert sum(sample.scenario == "failure_burst" for sample in samples) == 6


def test_build_evaluation_samples_has_four_multi_account_samples() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert sum(sample.scenario == "multi_account" for sample in samples) == 4


def test_normal_samples_are_not_labeled_injected_suspicious() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert all(
        not sample.is_injected_suspicious
        for sample in samples
        if sample.scenario == "normal"
    )


def test_injected_scenario_samples_are_labeled_suspicious() -> None:
    samples = build_evaluation_samples(normal_count=5, start_time=START_TIME)

    assert all(
        sample.is_injected_suspicious
        for sample in samples
        if sample.scenario != "normal"
    )


def test_evaluation_sample_order_is_normal_then_injected_scenarios() -> None:
    samples = build_evaluation_samples(normal_count=3, start_time=START_TIME)

    assert [sample.scenario for sample in samples] == [
        *(["normal"] * 3),
        *(["failure_burst"] * 6),
        *(["multi_account"] * 4),
    ]


def test_build_evaluation_samples_is_reproducible() -> None:
    first = build_evaluation_samples(
        normal_count=10,
        normal_seed=777,
        start_time=START_TIME,
    )
    second = build_evaluation_samples(
        normal_count=10,
        normal_seed=777,
        start_time=START_TIME,
    )

    assert first == second


def test_evaluate_predictions_rejects_different_lengths() -> None:
    record = make_feature_record()
    samples = [EvaluationSample(record, False, "normal")]

    with pytest.raises(ValueError):
        evaluate_predictions(samples, [])


def test_evaluate_predictions_rejects_misaligned_feature_record() -> None:
    sample = EvaluationSample(make_feature_record(), False, "normal")
    prediction = AnomalyPrediction(make_feature_record(), 0.0, False)

    with pytest.raises(ValueError):
        evaluate_predictions([sample], [prediction])


def test_empty_evaluation_has_zero_counts_and_metrics() -> None:
    assert evaluate_predictions([], []) == EvaluationResult(
        sample_count=0,
        injected_suspicious_count=0,
        normal_count=0,
        predicted_anomaly_count=0,
        true_positive=0,
        false_positive=0,
        true_negative=0,
        false_negative=0,
        precision=0.0,
        recall=0.0,
        f1=0.0,
    )


def test_evaluation_calculates_true_positive() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).true_positive == 1


def test_evaluation_calculates_false_positive() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).false_positive == 1


def test_evaluation_calculates_true_negative() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).true_negative == 1


def test_evaluation_calculates_false_negative() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).false_negative == 1


def test_evaluation_calculates_precision() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).precision == pytest.approx(0.5)


def test_evaluation_calculates_recall() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).recall == pytest.approx(0.5)


def test_evaluation_calculates_f1() -> None:
    samples, predictions = metric_case()

    assert evaluate_predictions(samples, predictions).f1 == pytest.approx(0.5)


def test_evaluation_metrics_avoid_division_by_zero() -> None:
    record = make_feature_record()
    sample = EvaluationSample(record, False, "normal")
    prediction = AnomalyPrediction(record, 0.0, False)

    result = evaluate_predictions([sample], [prediction])

    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_run_synthetic_evaluation_produces_prediction_per_sample() -> None:
    _, samples, predictions = run_synthetic_evaluation(
        normal_training_records(),
        normal_count=10,
        start_time=START_TIME,
    )

    assert len(predictions) == len(samples)


def test_run_synthetic_evaluation_has_consistent_sample_count() -> None:
    result, samples, _ = run_synthetic_evaluation(
        normal_training_records(),
        normal_count=10,
        start_time=START_TIME,
    )

    assert result.sample_count == len(samples)


def test_run_synthetic_evaluation_has_consistent_anomaly_count() -> None:
    result, _, predictions = run_synthetic_evaluation(
        normal_training_records(),
        normal_count=10,
        start_time=START_TIME,
    )

    assert result.predicted_anomaly_count == sum(
        prediction.is_anomaly for prediction in predictions
    )


def test_run_synthetic_evaluation_is_reproducible() -> None:
    training_records = normal_training_records()
    first = run_synthetic_evaluation(
        training_records,
        random_state=7,
        normal_count=10,
        normal_seed=777,
        start_time=START_TIME,
    )
    second = run_synthetic_evaluation(
        training_records,
        random_state=7,
        normal_count=10,
        normal_seed=777,
        start_time=START_TIME,
    )

    assert first == second
