"""Reproducible evaluation on controlled synthetic scenarios."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.ml import AnomalyPrediction, predict_anomalies, train_isolation_forest


@dataclass(frozen=True)
class EvaluationSample:
    """A feature record labeled only by its synthetic scenario origin."""

    feature_record: AuthEventFeatures
    is_injected_suspicious: bool
    scenario: str


@dataclass(frozen=True)
class EvaluationResult:
    """Metrics for recovering injected suspicious synthetic scenarios."""

    sample_count: int
    injected_suspicious_count: int
    normal_count: int
    predicted_anomaly_count: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float


def build_evaluation_samples(
    *,
    normal_count: int = 100,
    normal_seed: int = 999,
    start_time: datetime,
) -> list[EvaluationSample]:
    """Build ordered samples from normal and injected synthetic scenarios."""
    if normal_count <= 0:
        raise ValueError("normal_count must be greater than zero")
    if start_time.tzinfo is None or start_time.utcoffset() is None:
        raise ValueError("start_time must include timezone information")

    normal_features = compute_auth_features(
        generate_normal_events(normal_count, seed=normal_seed)
    )
    failure_burst_features = compute_auth_features(
        generate_failure_burst(attempts=6, start_time=start_time)
    )
    multi_account_features = compute_auth_features(
        generate_multi_account_activity(
            user_ids=[
                "eval-user-a",
                "eval-user-b",
                "eval-user-c",
                "eval-user-d",
            ],
            start_time=start_time + timedelta(minutes=10),
        )
    )

    return [
        *(
            EvaluationSample(
                feature_record=feature_record,
                is_injected_suspicious=False,
                scenario="normal",
            )
            for feature_record in normal_features
        ),
        *(
            EvaluationSample(
                feature_record=feature_record,
                is_injected_suspicious=True,
                scenario="failure_burst",
            )
            for feature_record in failure_burst_features
        ),
        *(
            EvaluationSample(
                feature_record=feature_record,
                is_injected_suspicious=True,
                scenario="multi_account",
            )
            for feature_record in multi_account_features
        ),
    ]


def evaluate_predictions(
    samples: list[EvaluationSample],
    predictions: list[AnomalyPrediction],
) -> EvaluationResult:
    """Compare anomaly predictions with synthetic scenario-origin labels."""
    if len(samples) != len(predictions):
        raise ValueError("samples and predictions must have the same length")
    if any(
        sample.feature_record is not prediction.feature_record
        for sample, prediction in zip(samples, predictions, strict=True)
    ):
        raise ValueError("samples and predictions must be aligned")

    true_positive = sum(
        sample.is_injected_suspicious and prediction.is_anomaly
        for sample, prediction in zip(samples, predictions, strict=True)
    )
    false_positive = sum(
        not sample.is_injected_suspicious and prediction.is_anomaly
        for sample, prediction in zip(samples, predictions, strict=True)
    )
    true_negative = sum(
        not sample.is_injected_suspicious and not prediction.is_anomaly
        for sample, prediction in zip(samples, predictions, strict=True)
    )
    false_negative = sum(
        sample.is_injected_suspicious and not prediction.is_anomaly
        for sample, prediction in zip(samples, predictions, strict=True)
    )

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = (
        true_positive / precision_denominator if precision_denominator else 0.0
    )
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1_denominator = precision + recall
    f1 = 2 * precision * recall / f1_denominator if f1_denominator else 0.0

    return EvaluationResult(
        sample_count=len(samples),
        injected_suspicious_count=sum(
            sample.is_injected_suspicious for sample in samples
        ),
        normal_count=sum(not sample.is_injected_suspicious for sample in samples),
        predicted_anomaly_count=sum(
            prediction.is_anomaly for prediction in predictions
        ),
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
    )


def run_synthetic_evaluation(
    training_records: list[AuthEventFeatures],
    *,
    contamination: float | str = "auto",
    random_state: int = 42,
    normal_count: int = 100,
    normal_seed: int = 999,
    start_time: datetime,
) -> tuple[EvaluationResult, list[EvaluationSample], list[AnomalyPrediction]]:
    """Train on supplied records and evaluate controlled synthetic samples."""
    samples = build_evaluation_samples(
        normal_count=normal_count,
        normal_seed=normal_seed,
        start_time=start_time,
    )
    model = train_isolation_forest(
        training_records,
        contamination=contamination,
        random_state=random_state,
    )
    predictions = predict_anomalies(
        model,
        [sample.feature_record for sample in samples],
    )
    result = evaluate_predictions(samples, predictions)
    return result, samples, predictions
