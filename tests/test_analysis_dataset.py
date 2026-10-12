from datetime import datetime, timedelta, timezone

import pandas as pd

from app.analysis import (
    FEATURE_COLUMNS,
    extract_feature_matrix,
    feature_records_to_dataframe,
    summarize_feature_records,
)
from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.models import AuthenticationEvent


START_TIME = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
DATAFRAME_COLUMNS = [
    "timestamp",
    "user_id",
    "source_ip",
    "result",
    "service",
    "attempts_5m",
    "failed_attempts_5m",
    "unique_users_per_ip_5m",
    "unique_ips_per_user_30m",
]


def make_feature_records() -> list[AuthEventFeatures]:
    values = [
        ("user-a", "192.0.2.10", "success", "vpn", 1, 0, 1, 1),
        ("user-b", "192.0.2.20", "failure", "email", 3, 2, 2, 3),
        ("user-a", "192.0.2.20", "failure", "web_portal", 5, 4, 3, 2),
    ]
    records: list[AuthEventFeatures] = []
    for index, (
        user_id,
        source_ip,
        result,
        service,
        attempts,
        failures,
        unique_users,
        unique_ips,
    ) in enumerate(values):
        event = AuthenticationEvent(
            timestamp=START_TIME + timedelta(minutes=index),
            user_id=user_id,
            source_ip=source_ip,
            result=result,
            service=service,
        )
        records.append(
            AuthEventFeatures(
                event=event,
                attempts_5m=attempts,
                failed_attempts_5m=failures,
                unique_users_per_ip_5m=unique_users,
                unique_ips_per_user_30m=unique_ips,
            )
        )
    return records


def test_feature_columns_have_exact_order() -> None:
    assert FEATURE_COLUMNS == [
        "attempts_5m",
        "failed_attempts_5m",
        "unique_users_per_ip_5m",
        "unique_ips_per_user_30m",
    ]


def test_empty_dataframe_has_exact_columns() -> None:
    dataframe = feature_records_to_dataframe([])

    assert dataframe.empty
    assert list(dataframe.columns) == DATAFRAME_COLUMNS


def test_dataframe_has_one_row_per_feature_record() -> None:
    records = make_feature_records()

    assert len(feature_records_to_dataframe(records)) == len(records)


def test_dataframe_preserves_row_order() -> None:
    dataframe = feature_records_to_dataframe(make_feature_records())

    assert dataframe["user_id"].tolist() == ["user-a", "user-b", "user-a"]


def test_dataframe_copies_event_metadata() -> None:
    record = make_feature_records()[1]

    row = feature_records_to_dataframe([record]).iloc[0]

    assert row["timestamp"] == record.event.timestamp
    assert row["user_id"] == "user-b"
    assert row["result"] == "failure"
    assert row["service"] == "email"


def test_dataframe_converts_source_ip_to_string() -> None:
    dataframe = feature_records_to_dataframe(make_feature_records())

    assert dataframe["source_ip"].tolist() == [
        "192.0.2.10",
        "192.0.2.20",
        "192.0.2.20",
    ]
    assert all(isinstance(value, str) for value in dataframe["source_ip"])


def test_dataframe_copies_numeric_features() -> None:
    dataframe = feature_records_to_dataframe(make_feature_records())

    assert dataframe[FEATURE_COLUMNS].to_dict(orient="records") == [
        {
            "attempts_5m": 1,
            "failed_attempts_5m": 0,
            "unique_users_per_ip_5m": 1,
            "unique_ips_per_user_30m": 1,
        },
        {
            "attempts_5m": 3,
            "failed_attempts_5m": 2,
            "unique_users_per_ip_5m": 2,
            "unique_ips_per_user_30m": 3,
        },
        {
            "attempts_5m": 5,
            "failed_attempts_5m": 4,
            "unique_users_per_ip_5m": 3,
            "unique_ips_per_user_30m": 2,
        },
    ]


def test_feature_matrix_has_exact_columns() -> None:
    matrix = extract_feature_matrix(make_feature_records())

    assert list(matrix.columns) == FEATURE_COLUMNS


def test_feature_matrix_contains_only_numeric_values() -> None:
    matrix = extract_feature_matrix(make_feature_records())

    assert all(pd.api.types.is_numeric_dtype(dtype) for dtype in matrix.dtypes)


def test_feature_matrix_preserves_row_order() -> None:
    matrix = extract_feature_matrix(make_feature_records())

    assert matrix["attempts_5m"].tolist() == [1, 3, 5]


def test_empty_feature_matrix_has_expected_structure() -> None:
    matrix = extract_feature_matrix([])

    assert matrix.empty
    assert list(matrix.columns) == FEATURE_COLUMNS


def test_empty_summary_has_expected_values() -> None:
    assert summarize_feature_records([]) == {
        "event_count": 0,
        "failure_count": 0,
        "success_count": 0,
        "unique_users": 0,
        "unique_source_ips": 0,
        "feature_min": {},
        "feature_max": {},
        "feature_mean": {},
    }


def test_summary_has_correct_event_count() -> None:
    assert summarize_feature_records(make_feature_records())["event_count"] == 3


def test_summary_has_correct_result_counts() -> None:
    summary = summarize_feature_records(make_feature_records())

    assert summary["success_count"] == 1
    assert summary["failure_count"] == 2


def test_summary_has_correct_unique_user_count() -> None:
    assert summarize_feature_records(make_feature_records())["unique_users"] == 2


def test_summary_has_correct_unique_source_ip_count() -> None:
    summary = summarize_feature_records(make_feature_records())

    assert summary["unique_source_ips"] == 2


def test_summary_has_correct_feature_minimums() -> None:
    summary = summarize_feature_records(make_feature_records())

    assert summary["feature_min"] == {
        "attempts_5m": 1,
        "failed_attempts_5m": 0,
        "unique_users_per_ip_5m": 1,
        "unique_ips_per_user_30m": 1,
    }


def test_summary_has_correct_feature_maximums() -> None:
    summary = summarize_feature_records(make_feature_records())

    assert summary["feature_max"] == {
        "attempts_5m": 5,
        "failed_attempts_5m": 4,
        "unique_users_per_ip_5m": 3,
        "unique_ips_per_user_30m": 3,
    }


def test_summary_has_correct_feature_means() -> None:
    summary = summarize_feature_records(make_feature_records())

    assert summary["feature_mean"] == {
        "attempts_5m": 3.0,
        "failed_attempts_5m": 2.0,
        "unique_users_per_ip_5m": 2.0,
        "unique_ips_per_user_30m": 2.0,
    }


def test_normal_events_pipeline_produces_dataframe() -> None:
    events = generate_normal_events(20, seed=123)
    records = compute_auth_features(events)

    dataframe = feature_records_to_dataframe(records)

    assert len(dataframe) == len(events)
    assert list(dataframe.columns) == DATAFRAME_COLUMNS


def test_failure_burst_summary_reports_high_failed_attempt_count() -> None:
    events = generate_failure_burst(attempts=6, start_time=START_TIME)
    records = compute_auth_features(events)

    summary = summarize_feature_records(records)

    assert summary["feature_max"]["failed_attempts_5m"] == 6


def test_multi_account_summary_reports_high_unique_user_count() -> None:
    events = generate_multi_account_activity(
        user_ids=["user-a", "user-b", "user-c", "user-d"],
        start_time=START_TIME,
    )
    records = compute_auth_features(events)

    summary = summarize_feature_records(records)

    assert summary["feature_max"]["unique_users_per_ip_5m"] == 4
