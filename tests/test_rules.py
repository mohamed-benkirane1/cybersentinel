from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.detection import (
    RuleMatch,
    evaluate_feature_batch,
    evaluate_r001,
    evaluate_r002,
    evaluate_rules,
)
from app.features import AuthEventFeatures, compute_auth_features
from app.models import AuthenticationEvent


START_TIME = datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc)


def make_features(
    *,
    timestamp: datetime = START_TIME,
    user_id: str = "user-a",
    source_ip: str = "192.0.2.10",
    failed_attempts_5m: int = 0,
    unique_users_per_ip_5m: int = 1,
) -> AuthEventFeatures:
    event = AuthenticationEvent(
        timestamp=timestamp,
        user_id=user_id,
        source_ip=source_ip,
        result="failure" if failed_attempts_5m else "success",
        service="vpn",
    )
    return AuthEventFeatures(
        event=event,
        attempts_5m=max(1, failed_attempts_5m),
        failed_attempts_5m=failed_attempts_5m,
        unique_users_per_ip_5m=unique_users_per_ip_5m,
        unique_ips_per_user_30m=1,
    )


def test_rule_match_is_immutable() -> None:
    match = evaluate_r001(make_features(failed_attempts_5m=5))

    assert match is not None
    with pytest.raises(FrozenInstanceError):
        match.severity = "low"


def test_r001_does_not_trigger_below_threshold() -> None:
    assert evaluate_r001(make_features(failed_attempts_5m=4)) is None


def test_r001_triggers_at_threshold() -> None:
    assert evaluate_r001(make_features(failed_attempts_5m=5)) is not None


def test_r001_triggers_above_threshold() -> None:
    assert evaluate_r001(make_features(failed_attempts_5m=6)) is not None


@pytest.mark.parametrize("threshold", [0, -1])
def test_r001_rejects_non_positive_threshold(threshold: int) -> None:
    with pytest.raises(ValueError):
        evaluate_r001(make_features(), threshold=threshold)


def test_r001_has_expected_rule_id() -> None:
    match = evaluate_r001(make_features(failed_attempts_5m=5))

    assert match is not None
    assert match.rule_id == "R001"


def test_r001_has_expected_evidence() -> None:
    match = evaluate_r001(
        make_features(user_id="target-user", failed_attempts_5m=7),
        threshold=6,
    )

    assert match is not None
    assert match.evidence == {
        "user_id": "target-user",
        "failed_attempts_5m": 7,
        "threshold": 6,
    }
    assert match.severity == "high"
    assert match.timestamp == START_TIME


def test_r002_does_not_trigger_below_threshold() -> None:
    assert evaluate_r002(make_features(unique_users_per_ip_5m=3)) is None


def test_r002_triggers_at_threshold() -> None:
    assert evaluate_r002(make_features(unique_users_per_ip_5m=4)) is not None


def test_r002_triggers_above_threshold() -> None:
    assert evaluate_r002(make_features(unique_users_per_ip_5m=5)) is not None


@pytest.mark.parametrize("threshold", [0, -1])
def test_r002_rejects_non_positive_threshold(threshold: int) -> None:
    with pytest.raises(ValueError):
        evaluate_r002(make_features(), threshold=threshold)


def test_r002_has_expected_rule_id() -> None:
    match = evaluate_r002(make_features(unique_users_per_ip_5m=4))

    assert match is not None
    assert match.rule_id == "R002"


def test_r002_has_expected_evidence() -> None:
    match = evaluate_r002(
        make_features(source_ip="198.51.100.20", unique_users_per_ip_5m=6),
        threshold=5,
    )

    assert match is not None
    assert match.evidence == {
        "source_ip": "198.51.100.20",
        "unique_users_per_ip_5m": 6,
        "threshold": 5,
    }
    assert match.severity == "high"
    assert match.timestamp == START_TIME


def test_evaluate_rules_returns_empty_list_when_no_rule_triggers() -> None:
    assert evaluate_rules(make_features()) == []


def test_evaluate_rules_can_return_only_r001() -> None:
    matches = evaluate_rules(
        make_features(failed_attempts_5m=5, unique_users_per_ip_5m=3)
    )

    assert [match.rule_id for match in matches] == ["R001"]


def test_evaluate_rules_can_return_only_r002() -> None:
    matches = evaluate_rules(
        make_features(failed_attempts_5m=4, unique_users_per_ip_5m=4)
    )

    assert [match.rule_id for match in matches] == ["R002"]


def test_evaluate_rules_returns_r001_then_r002() -> None:
    matches = evaluate_rules(
        make_features(failed_attempts_5m=5, unique_users_per_ip_5m=4)
    )

    assert [match.rule_id for match in matches] == ["R001", "R002"]


def test_evaluate_feature_batch_returns_empty_list_for_empty_input() -> None:
    assert evaluate_feature_batch([]) == []


def test_evaluate_feature_batch_preserves_result_order() -> None:
    first = make_features(
        timestamp=START_TIME,
        failed_attempts_5m=0,
        unique_users_per_ip_5m=4,
    )
    second = make_features(
        timestamp=START_TIME + timedelta(seconds=1),
        failed_attempts_5m=5,
        unique_users_per_ip_5m=4,
    )

    matches = evaluate_feature_batch([first, second])

    assert [match.rule_id for match in matches] == ["R002", "R001", "R002"]
    assert [match.timestamp for match in matches] == [
        START_TIME,
        START_TIME + timedelta(seconds=1),
        START_TIME + timedelta(seconds=1),
    ]


def test_failure_burst_triggers_r001_on_last_event() -> None:
    events = generate_failure_burst(attempts=6, start_time=START_TIME)
    features = compute_auth_features(events)

    assert "R001" in {
        match.rule_id for match in evaluate_rules(features[-1])
    }


def test_multi_account_activity_triggers_r002_on_last_event() -> None:
    events = generate_multi_account_activity(
        user_ids=["user-a", "user-b", "user-c", "user-d"],
        start_time=START_TIME,
    )
    features = compute_auth_features(events)

    assert "R002" in {
        match.rule_id for match in evaluate_rules(features[-1])
    }


def test_normal_events_can_flow_through_rule_engine() -> None:
    events = generate_normal_events(20, seed=123)
    features = compute_auth_features(events)

    matches = evaluate_feature_batch(features)

    assert isinstance(matches, list)
    assert [match.timestamp for match in matches] == sorted(
        match.timestamp for match in matches
    )
