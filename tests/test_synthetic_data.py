from datetime import timedelta

import pytest

from app.data import generate_normal_events
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
