from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from math import isfinite

import pytest
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

from app.analysis import FEATURE_COLUMNS, extract_feature_matrix
from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.ml import (
    AnomalyPrediction,
    predict_anomalies,
    train_and_predict,
    train_isolation_forest,
)


START_TIME = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)


def normal_feature_records(count: int = 80) -> list[AuthEventFeatures]:
    return compute_auth_features(generate_normal_events(count, seed=123))


def test_anomaly_prediction_is_immutable() -> None:
    feature_record = normal_feature_records(1)[0]
    prediction = AnomalyPrediction(
        feature_record=feature_record,
        anomaly_score=0.1,
        is_anomaly=False,
    )

    with pytest.raises(FrozenInstanceError):
        prediction.anomaly_score = 0.2


def test_train_isolation_forest_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        train_isolation_forest([])


def test_train_isolation_forest_returns_trained_model() -> None:
    model = train_isolation_forest(normal_feature_records())

    assert isinstance(model, IsolationForest)
    assert model.n_estimators == 100
    assert hasattr(model, "estimators_")
    assert model.feature_names_in_.tolist() == FEATURE_COLUMNS


def test_train_isolation_forest_accepts_auto_contamination() -> None:
    model = train_isolation_forest(
        normal_feature_records(),
        contamination="auto",
    )

    assert model.contamination == "auto"


def test_train_isolation_forest_accepts_float_contamination() -> None:
    model = train_isolation_forest(
        normal_feature_records(),
        contamination=0.1,
    )

    assert model.contamination == 0.1


def test_train_isolation_forest_rejects_invalid_contamination_string() -> None:
    with pytest.raises(ValueError):
        train_isolation_forest(
            normal_feature_records(),
            contamination="invalid",
        )


def test_same_random_state_produces_reproducible_results() -> None:
    records = normal_feature_records()
    matrix = extract_feature_matrix(records)
    first_model = train_isolation_forest(records, random_state=7)
    second_model = train_isolation_forest(records, random_state=7)

    assert first_model.predict(matrix).tolist() == second_model.predict(matrix).tolist()
    assert first_model.decision_function(matrix).tolist() == pytest.approx(
        second_model.decision_function(matrix).tolist()
    )


def test_predict_anomalies_returns_empty_list_for_empty_input() -> None:
    assert predict_anomalies(IsolationForest(), []) == []


def test_predict_anomalies_returns_one_prediction_per_record() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)

    assert len(predict_anomalies(model, records)) == len(records)


def test_predict_anomalies_preserves_feature_record_order() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)

    predictions = predict_anomalies(model, records)

    assert [prediction.feature_record for prediction in predictions] == records


def test_prediction_references_original_feature_record_objects() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)

    predictions = predict_anomalies(model, records)

    assert all(
        prediction.feature_record is record
        for prediction, record in zip(predictions, records, strict=True)
    )


def test_anomaly_score_is_python_float() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)

    predictions = predict_anomalies(model, records)

    assert all(type(prediction.anomaly_score) is float for prediction in predictions)


def test_is_anomaly_is_python_bool() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)

    predictions = predict_anomalies(model, records)

    assert all(type(prediction.is_anomaly) is bool for prediction in predictions)


def test_is_anomaly_matches_sklearn_prediction_labels() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records, contamination=0.1)
    matrix = extract_feature_matrix(records)

    predictions = predict_anomalies(model, records)
    sklearn_labels = model.predict(matrix)

    assert [prediction.is_anomaly for prediction in predictions] == [
        bool(label == -1) for label in sklearn_labels
    ]


def test_anomaly_score_is_negative_decision_function() -> None:
    records = normal_feature_records()
    model = train_isolation_forest(records)
    matrix = extract_feature_matrix(records)

    predictions = predict_anomalies(model, records)
    expected_scores = [-float(score) for score in model.decision_function(matrix)]

    assert [prediction.anomaly_score for prediction in predictions] == pytest.approx(
        expected_scores
    )


def test_untrained_model_raises_sklearn_not_fitted_error() -> None:
    with pytest.raises(NotFittedError):
        predict_anomalies(IsolationForest(), normal_feature_records(2))


def test_train_and_predict_matches_manual_calls() -> None:
    training_records = normal_feature_records()
    prediction_records = normal_feature_records(10)
    model = train_isolation_forest(
        training_records,
        contamination=0.1,
        random_state=9,
    )

    manual_predictions = predict_anomalies(model, prediction_records)
    convenience_predictions = train_and_predict(
        training_records,
        prediction_records,
        contamination=0.1,
        random_state=9,
    )

    assert convenience_predictions == manual_predictions


def test_failure_burst_pipeline_produces_finite_predictions() -> None:
    model = train_isolation_forest(normal_feature_records())
    events = generate_failure_burst(attempts=6, start_time=START_TIME)
    records = compute_auth_features(events)

    predictions = predict_anomalies(model, records)

    assert len(predictions) == len(events)
    assert all(isfinite(prediction.anomaly_score) for prediction in predictions)


def test_multi_account_pipeline_produces_finite_predictions() -> None:
    model = train_isolation_forest(normal_feature_records())
    events = generate_multi_account_activity(
        user_ids=["user-a", "user-b", "user-c", "user-d"],
        start_time=START_TIME,
    )
    records = compute_auth_features(events)

    predictions = predict_anomalies(model, records)

    assert len(predictions) == len(events)
    assert all(isfinite(prediction.anomaly_score) for prediction in predictions)
