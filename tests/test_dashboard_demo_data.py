from datetime import datetime, timezone

import pytest

from app.dashboard.demo_data import (
    DEMO_SCENARIOS,
    FAILURE_BURST_SCENARIO,
    MULTI_ACCOUNT_SCENARIO,
    NORMAL_SCENARIO,
    build_demo_events,
)
from app.models import AuthenticationEvent


START_TIME = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


def test_demo_scenarios_have_exact_order() -> None:
    assert DEMO_SCENARIOS == (
        "Normal traffic",
        "Failure burst",
        "Multi-account activity",
    )


def test_normal_scenario_produces_ten_events() -> None:
    assert len(build_demo_events(NORMAL_SCENARIO, start_time=START_TIME)) == 10


def test_normal_scenario_is_reproducible() -> None:
    first = build_demo_events(NORMAL_SCENARIO, start_time=START_TIME)
    second = build_demo_events(NORMAL_SCENARIO, start_time=START_TIME)

    assert first == second


def test_failure_burst_scenario_produces_six_events() -> None:
    events = build_demo_events(FAILURE_BURST_SCENARIO, start_time=START_TIME)

    assert len(events) == 6


def test_failure_burst_scenario_contains_only_failures() -> None:
    events = build_demo_events(FAILURE_BURST_SCENARIO, start_time=START_TIME)

    assert {event.result for event in events} == {"failure"}


def test_multi_account_scenario_produces_four_events() -> None:
    events = build_demo_events(MULTI_ACCOUNT_SCENARIO, start_time=START_TIME)

    assert len(events) == 4


def test_multi_account_scenario_contains_four_distinct_users() -> None:
    events = build_demo_events(MULTI_ACCOUNT_SCENARIO, start_time=START_TIME)

    assert len({event.user_id for event in events}) == 4


def test_unknown_scenario_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_demo_events("unknown", start_time=START_TIME)


@pytest.mark.parametrize("scenario", DEMO_SCENARIOS)
def test_demo_scenarios_produce_authentication_events(scenario: str) -> None:
    events = build_demo_events(scenario, start_time=START_TIME)

    assert all(isinstance(event, AuthenticationEvent) for event in events)
