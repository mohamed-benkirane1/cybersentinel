from datetime import datetime, timedelta, timezone

import pytest

from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.models import AuthenticationEvent


def test_generate_exact_event_count() -> None:
    events = generate_normal_events(25)

    assert len(events) == 25


def test_all_events_are_authentication_events() -> None:
    events = generate_normal_events(20)

    assert all(isinstance(event, AuthenticationEvent) for event in events)


def test_generation_is_reproducible_with_same_seed() -> None:
    assert generate_normal_events(30, seed=1234) == generate_normal_events(
        30, seed=1234
    )


def test_events_are_chronological_and_in_utc() -> None:
    events = generate_normal_events(40)
    timestamps = [event.timestamp for event in events]

    assert timestamps == sorted(timestamps)
    assert all(timestamp.utcoffset() == timedelta(0) for timestamp in timestamps)


def test_normal_sample_contains_mostly_successes_and_some_failures() -> None:
    events = generate_normal_events(100)
    results = [event.result for event in events]

    assert "success" in results
    assert "failure" in results
    assert results.count("success") > results.count("failure")


def test_services_are_limited_to_allowed_values() -> None:
    events = generate_normal_events(50)

    assert {event.service for event in events} <= {"vpn", "web_portal", "email"}


def test_sample_contains_multiple_synthetic_users_and_source_ips() -> None:
    events = generate_normal_events(20)

    assert len({event.user_id for event in events}) > 1
    assert len({event.source_ip for event in events}) > 1


@pytest.mark.parametrize("count", [0, -1, -100])
def test_non_positive_count_is_rejected(count: int) -> None:
    with pytest.raises(ValueError):
        generate_normal_events(count)


def test_failure_burst_has_expected_shape() -> None:
    start_time = datetime(2026, 2, 1, 8, 0, tzinfo=timezone.utc)

    events = generate_failure_burst(
        attempts=6,
        start_time=start_time,
        user_id="synthetic-user-target",
        source_ip="192.0.2.200",
        service="vpn",
    )

    assert len(events) == 6
    assert {event.user_id for event in events} == {"synthetic-user-target"}
    assert {str(event.source_ip) for event in events} == {"192.0.2.200"}
    assert {event.service for event in events} == {"vpn"}
    assert {event.result for event in events} == {"failure"}
    assert [event.timestamp for event in events] == sorted(
        event.timestamp for event in events
    )
    assert all(event.timestamp.utcoffset() == timedelta(0) for event in events)


@pytest.mark.parametrize("attempts", [0, -1])
def test_failure_burst_rejects_non_positive_attempts(attempts: int) -> None:
    with pytest.raises(ValueError):
        generate_failure_burst(
            attempts=attempts,
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_failure_burst_rejects_start_time_without_timezone() -> None:
    with pytest.raises(ValueError):
        generate_failure_burst(
            attempts=5,
            start_time=datetime(2026, 2, 1),
        )


def test_multi_account_activity_has_expected_shape() -> None:
    user_ids = [
        "synthetic-user-a",
        "synthetic-user-b",
        "synthetic-user-c",
        "synthetic-user-d",
    ]
    start_time = datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc)

    events = generate_multi_account_activity(
        user_ids=user_ids,
        start_time=start_time,
        source_ip="198.51.100.200",
        service="email",
    )

    assert len(events) == len(user_ids)
    assert [event.user_id for event in events] == user_ids
    assert len({event.user_id for event in events}) > 1
    assert {str(event.source_ip) for event in events} == {"198.51.100.200"}
    assert {event.service for event in events} == {"email"}
    assert {event.result for event in events} == {"failure"}
    assert [event.timestamp for event in events] == sorted(
        event.timestamp for event in events
    )
    assert all(event.timestamp.utcoffset() == timedelta(0) for event in events)


def test_multi_account_activity_rejects_empty_user_ids() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=[],
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_multi_account_activity_rejects_single_user_id() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=["synthetic-user-a"],
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_multi_account_activity_rejects_duplicate_user_ids() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=["synthetic-user-a", "synthetic-user-a"],
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_multi_account_activity_rejects_duplicates_after_stripping() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=["synthetic-user-a", " synthetic-user-a "],
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_multi_account_activity_rejects_whitespace_only_user_id() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=["synthetic-user-a", "   "],
            start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )


def test_multi_account_activity_normalizes_user_ids_and_preserves_order() -> None:
    events = generate_multi_account_activity(
        user_ids=[" synthetic-user-a ", "synthetic-user-b "],
        start_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    assert [event.user_id for event in events] == [
        "synthetic-user-a",
        "synthetic-user-b",
    ]


def test_multi_account_activity_rejects_start_time_without_timezone() -> None:
    with pytest.raises(ValueError):
        generate_multi_account_activity(
            user_ids=["synthetic-user-a", "synthetic-user-b"],
            start_time=datetime(2026, 2, 1),
        )
