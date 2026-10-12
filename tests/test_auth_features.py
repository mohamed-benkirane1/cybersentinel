from datetime import datetime, timedelta, timezone

import pytest

from app.data import generate_failure_burst, generate_multi_account_activity
from app.features import AuthEventFeatures, compute_auth_features
from app.models import AuthenticationEvent


START_TIME = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)


def make_event(
    timestamp: datetime,
    *,
    user_id: str = "user-a",
    source_ip: str = "192.0.2.10",
    result: str = "success",
) -> AuthenticationEvent:
    return AuthenticationEvent(
        timestamp=timestamp,
        user_id=user_id,
        source_ip=source_ip,
        result=result,
        service="vpn",
    )


def test_empty_event_list_returns_empty_features() -> None:
    assert compute_auth_features([]) == []


def test_single_event_has_initial_feature_values() -> None:
    event = make_event(START_TIME)

    assert compute_auth_features([event]) == [
        AuthEventFeatures(
            event=event,
            attempts_5m=1,
            failed_attempts_5m=0,
            unique_users_per_ip_5m=1,
            unique_ips_per_user_30m=1,
        )
    ]


def test_attempts_5m_counts_success_and_failure_for_same_user() -> None:
    events = [
        make_event(START_TIME, result="success"),
        make_event(START_TIME + timedelta(minutes=1), result="failure"),
    ]

    features = compute_auth_features(events)

    assert [feature.attempts_5m for feature in features] == [1, 2]


def test_failed_attempts_5m_counts_only_failures() -> None:
    events = [
        make_event(START_TIME, result="failure"),
        make_event(START_TIME + timedelta(minutes=1), result="success"),
        make_event(START_TIME + timedelta(minutes=2), result="failure"),
    ]

    features = compute_auth_features(events)

    assert [feature.failed_attempts_5m for feature in features] == [1, 1, 2]


def test_attempt_older_than_five_minutes_is_excluded() -> None:
    events = [
        make_event(START_TIME),
        make_event(START_TIME + timedelta(minutes=5, seconds=1)),
    ]

    assert compute_auth_features(events)[-1].attempts_5m == 1


def test_attempt_at_exact_five_minute_boundary_is_included() -> None:
    events = [
        make_event(START_TIME),
        make_event(START_TIME + timedelta(minutes=5)),
    ]

    assert compute_auth_features(events)[-1].attempts_5m == 2


def test_unique_users_per_ip_5m_counts_distinct_users() -> None:
    events = [
        make_event(START_TIME, user_id="user-a"),
        make_event(START_TIME + timedelta(minutes=1), user_id="user-b"),
        make_event(START_TIME + timedelta(minutes=2), user_id="user-c"),
    ]

    assert compute_auth_features(events)[-1].unique_users_per_ip_5m == 3


def test_repeated_user_does_not_inflate_unique_users_per_ip_5m() -> None:
    events = [
        make_event(START_TIME, user_id="user-a"),
        make_event(START_TIME + timedelta(minutes=1), user_id="user-a"),
        make_event(START_TIME + timedelta(minutes=2), user_id="user-b"),
    ]

    assert compute_auth_features(events)[-1].unique_users_per_ip_5m == 2


def test_unique_ips_per_user_30m_counts_distinct_ips() -> None:
    events = [
        make_event(START_TIME, source_ip="192.0.2.10"),
        make_event(START_TIME + timedelta(minutes=10), source_ip="192.0.2.20"),
        make_event(START_TIME + timedelta(minutes=20), source_ip="2001:db8::10"),
    ]

    assert compute_auth_features(events)[-1].unique_ips_per_user_30m == 3


def test_ip_older_than_thirty_minutes_is_excluded() -> None:
    events = [
        make_event(START_TIME, source_ip="192.0.2.10"),
        make_event(
            START_TIME + timedelta(minutes=30, seconds=1),
            source_ip="192.0.2.20",
        ),
    ]

    assert compute_auth_features(events)[-1].unique_ips_per_user_30m == 1


def test_ip_at_exact_thirty_minute_boundary_is_included() -> None:
    events = [
        make_event(START_TIME, source_ip="192.0.2.10"),
        make_event(START_TIME + timedelta(minutes=30), source_ip="192.0.2.20"),
    ]

    assert compute_auth_features(events)[-1].unique_ips_per_user_30m == 2


def test_output_preserves_event_order() -> None:
    events = [
        make_event(START_TIME, user_id="user-a"),
        make_event(START_TIME + timedelta(minutes=1), user_id="user-b"),
        make_event(START_TIME + timedelta(minutes=2), user_id="user-c"),
    ]

    features = compute_auth_features(events)

    assert [feature.event for feature in features] == events


def test_equal_timestamps_are_accepted() -> None:
    events = [
        make_event(START_TIME, result="success"),
        make_event(START_TIME, result="failure"),
    ]

    features = compute_auth_features(events)

    assert [feature.attempts_5m for feature in features] == [1, 2]


def test_non_chronological_events_are_rejected() -> None:
    events = [
        make_event(START_TIME + timedelta(seconds=1)),
        make_event(START_TIME),
    ]

    with pytest.raises(ValueError):
        compute_auth_features(events)


def test_naive_timestamp_is_rejected() -> None:
    event = make_event(datetime(2026, 3, 1, 10, 0))

    with pytest.raises(ValueError):
        compute_auth_features([event])


def test_input_events_are_not_modified() -> None:
    events = [make_event(START_TIME), make_event(START_TIME + timedelta(minutes=1))]
    original_values = [event.model_dump() for event in events]

    compute_auth_features(events)

    assert [event.model_dump() for event in events] == original_values


def test_failure_burst_last_event_counts_all_recent_failures() -> None:
    events = generate_failure_burst(attempts=6, start_time=START_TIME)

    assert compute_auth_features(events)[-1].failed_attempts_5m == 6


def test_multi_account_activity_last_event_counts_all_recent_users() -> None:
    events = generate_multi_account_activity(
        user_ids=["user-a", "user-b", "user-c", "user-d"],
        start_time=START_TIME,
    )

    assert compute_auth_features(events)[-1].unique_users_per_ip_5m == 4
