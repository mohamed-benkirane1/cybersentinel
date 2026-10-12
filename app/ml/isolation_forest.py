"""Isolation Forest baseline for authentication feature records."""

from dataclasses import dataclass

from sklearn.ensemble import IsolationForest

from app.analysis import FEATURE_COLUMNS, extract_feature_matrix
from app.features import AuthEventFeatures


@dataclass(frozen=True)
class AnomalyPrediction:
    """An Isolation Forest prediction associated with its feature record."""

    feature_record: AuthEventFeatures
    anomaly_score: float
    is_anomaly: bool


def train_isolation_forest(
    feature_records: list[AuthEventFeatures],
    *,
    contamination: float | str = "auto",
    random_state: int = 42,
) -> IsolationForest:
    """Train an Isolation Forest on the existing numeric feature matrix."""
    if not feature_records:
        raise ValueError("feature_records must not be empty")
    if isinstance(contamination, str) and contamination != "auto":
        raise ValueError("contamination string must be 'auto'")

    feature_matrix = extract_feature_matrix(feature_records).loc[:, FEATURE_COLUMNS]
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )
    return model.fit(feature_matrix)


def predict_anomalies(
    model: IsolationForest,
    feature_records: list[AuthEventFeatures],
) -> list[AnomalyPrediction]:
    """Predict statistical anomalies while preserving feature record order."""
    if not feature_records:
        return []

    feature_matrix = extract_feature_matrix(feature_records).loc[:, FEATURE_COLUMNS]
    labels = model.predict(feature_matrix)
    decision_scores = model.decision_function(feature_matrix)

    return [
        AnomalyPrediction(
            feature_record=feature_record,
            anomaly_score=float(-decision_score),
            is_anomaly=bool(label == -1),
        )
        for feature_record, label, decision_score in zip(
            feature_records,
            labels,
            decision_scores,
            strict=True,
        )
    ]


def train_and_predict(
    training_records: list[AuthEventFeatures],
    prediction_records: list[AuthEventFeatures],
    *,
    contamination: float | str = "auto",
    random_state: int = 42,
) -> list[AnomalyPrediction]:
    """Train the baseline model and predict records with it."""
    model = train_isolation_forest(
        training_records,
        contamination=contamination,
        random_state=random_state,
    )
    return predict_anomalies(model, prediction_records)
