"""Assemble inspectable tabular data from authentication features."""

import pandas as pd

from app.features import AuthEventFeatures


FEATURE_COLUMNS = [
    "attempts_5m",
    "failed_attempts_5m",
    "unique_users_per_ip_5m",
    "unique_ips_per_user_30m",
]

_DATAFRAME_COLUMNS = [
    "timestamp",
    "user_id",
    "source_ip",
    "result",
    "service",
    *FEATURE_COLUMNS,
]


def feature_records_to_dataframe(
    feature_records: list[AuthEventFeatures],
) -> pd.DataFrame:
    """Return one inspectable row per feature record in input order."""
    rows = [
        {
            "timestamp": record.event.timestamp,
            "user_id": record.event.user_id,
            "source_ip": str(record.event.source_ip),
            "result": record.event.result,
            "service": record.event.service,
            "attempts_5m": record.attempts_5m,
            "failed_attempts_5m": record.failed_attempts_5m,
            "unique_users_per_ip_5m": record.unique_users_per_ip_5m,
            "unique_ips_per_user_30m": record.unique_ips_per_user_30m,
        }
        for record in feature_records
    ]
    return pd.DataFrame(rows, columns=_DATAFRAME_COLUMNS)


def extract_feature_matrix(
    feature_records: list[AuthEventFeatures],
) -> pd.DataFrame:
    """Return only the numeric feature columns in input order."""
    rows = [
        {
            "attempts_5m": record.attempts_5m,
            "failed_attempts_5m": record.failed_attempts_5m,
            "unique_users_per_ip_5m": record.unique_users_per_ip_5m,
            "unique_ips_per_user_30m": record.unique_ips_per_user_30m,
        }
        for record in feature_records
    ]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def summarize_feature_records(
    feature_records: list[AuthEventFeatures],
) -> dict[str, object]:
    """Return counts and simple descriptive feature statistics."""
    if not feature_records:
        return {
            "event_count": 0,
            "failure_count": 0,
            "success_count": 0,
            "unique_users": 0,
            "unique_source_ips": 0,
            "feature_min": {},
            "feature_max": {},
            "feature_mean": {},
        }

    feature_matrix = extract_feature_matrix(feature_records)
    return {
        "event_count": len(feature_records),
        "failure_count": sum(
            record.event.result == "failure" for record in feature_records
        ),
        "success_count": sum(
            record.event.result == "success" for record in feature_records
        ),
        "unique_users": len(
            {record.event.user_id for record in feature_records}
        ),
        "unique_source_ips": len(
            {record.event.source_ip for record in feature_records}
        ),
        "feature_min": {
            column: int(feature_matrix[column].min()) for column in FEATURE_COLUMNS
        },
        "feature_max": {
            column: int(feature_matrix[column].max()) for column in FEATURE_COLUMNS
        },
        "feature_mean": {
            column: float(feature_matrix[column].mean())
            for column in FEATURE_COLUMNS
        },
    }
