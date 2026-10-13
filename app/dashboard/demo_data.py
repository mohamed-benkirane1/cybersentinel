"""Synthetic demonstration data for the Streamlit dashboard."""

from datetime import datetime

from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.models import AuthenticationEvent


NORMAL_SCENARIO = "Normal traffic"
FAILURE_BURST_SCENARIO = "Failure burst"
MULTI_ACCOUNT_SCENARIO = "Multi-account activity"

DEMO_SCENARIOS = (
    NORMAL_SCENARIO,
    FAILURE_BURST_SCENARIO,
    MULTI_ACCOUNT_SCENARIO,
)


def build_demo_events(
    scenario: str,
    *,
    start_time: datetime,
) -> list[AuthenticationEvent]:
    """Build synthetic authentication events for one demonstration scenario."""
    if scenario == NORMAL_SCENARIO:
        return generate_normal_events(10, seed=999)
    if scenario == FAILURE_BURST_SCENARIO:
        return generate_failure_burst(attempts=6, start_time=start_time)
    if scenario == MULTI_ACCOUNT_SCENARIO:
        return generate_multi_account_activity(
            user_ids=[
                "demo-user-a",
                "demo-user-b",
                "demo-user-c",
                "demo-user-d",
            ],
            start_time=start_time,
        )
    raise ValueError(f"unknown demo scenario: {scenario}")
