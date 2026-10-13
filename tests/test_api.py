from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from app.api import create_app
from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import compute_auth_features
from app.ml import train_isolation_forest


START_TIME = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
FEATURE_KEYS = {
    "attempts_5m",
    "failed_attempts_5m",
    "unique_users_per_ip_5m",
    "unique_ips_per_user_30m",
}


def valid_event(
    *,
    timestamp: str = "2026-09-01T10:00:00Z",
    user_id: str = "user-a",
    source_ip: str = "192.0.2.10",
    result: str = "success",
    service: str = "vpn",
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "user_id": user_id,
        "source_ip": source_ip,
        "result": result,
        "service": service,
    }


@pytest.fixture(scope="module")
def trained_model() -> IsolationForest:
    events = generate_normal_events(80, seed=321)
    return train_isolation_forest(compute_auth_features(events))


@pytest.fixture()
def client(trained_model: IsolationForest) -> TestClient:
    return TestClient(create_app(model=trained_model))


def test_create_app_returns_fastapi() -> None:
    assert isinstance(create_app(), FastAPI)


def test_health_returns_http_200(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_health_status_is_ok(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


def test_health_service_is_cybersentinel(client: TestClient) -> None:
    assert client.get("/health").json()["service"] == "cybersentinel"


def test_health_model_is_ready(client: TestClient) -> None:
    assert client.get("/health").json()["model_ready"] is True


def test_health_marks_service_as_prototype(client: TestClient) -> None:
    assert client.get("/health").json()["prototype"] is True


def test_analyze_accepts_valid_event(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assert response.status_code == 200


def test_analyze_assessment_count_matches_events(client: TestClient) -> None:
    events = [
        valid_event(),
        valid_event(
            timestamp="2026-09-01T10:00:05Z",
            user_id="user-b",
        ),
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.json()["assessment_count"] == len(events)


def test_analyze_returns_assessment_per_event(client: TestClient) -> None:
    events = [
        valid_event(),
        valid_event(
            timestamp="2026-09-01T10:00:05Z",
            user_id="user-b",
        ),
    ]

    response = client.post("/analyze", json={"events": events})

    assert len(response.json()["assessments"]) == len(events)


def test_analyze_preserves_event_order(client: TestClient) -> None:
    events = [
        valid_event(user_id="user-first"),
        valid_event(
            timestamp="2026-09-01T10:00:05Z",
            user_id="user-second",
        ),
    ]

    response = client.post("/analyze", json={"events": events})

    assert [
        assessment["user_id"] for assessment in response.json()["assessments"]
    ] == ["user-first", "user-second"]


def test_analyze_response_contains_four_features(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assessment = response.json()["assessments"][0]
    assert FEATURE_KEYS <= assessment.keys()


def test_analyze_response_contains_hybrid_risk_fields(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assessment = response.json()["assessments"][0]
    assert {"risk_score", "risk_level", "confidence"} <= assessment.keys()


def test_analyze_response_contains_ml_fields(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assessment = response.json()["assessments"][0]
    assert {"ml_anomaly_score", "ml_is_anomaly"} <= assessment.keys()


def test_analyze_returns_source_ip_as_string(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    source_ip = response.json()["assessments"][0]["source_ip"]
    assert source_ip == "192.0.2.10"
    assert type(source_ip) is str


def test_analyze_returns_reasons_as_list(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assert type(response.json()["assessments"][0]["reasons"]) is list


def test_analyze_returns_rule_matches_as_list(client: TestClient) -> None:
    response = client.post("/analyze", json={"events": [valid_event()]})

    assert type(response.json()["assessments"][0]["rule_matches"]) is list


def test_analyze_rejects_invalid_ip(client: TestClient) -> None:
    event = valid_event(source_ip="not-an-ip-address")

    assert client.post("/analyze", json={"events": [event]}).status_code == 422


def test_analyze_rejects_invalid_result(client: TestClient) -> None:
    event = valid_event(result="unknown")

    assert client.post("/analyze", json={"events": [event]}).status_code == 422


def test_analyze_rejects_missing_required_field(client: TestClient) -> None:
    event = valid_event()
    del event["user_id"]

    assert client.post("/analyze", json={"events": [event]}).status_code == 422


def test_analyze_rejects_extra_authentication_event_field(
    client: TestClient,
) -> None:
    event = valid_event()
    event["unexpected"] = "value"

    assert client.post("/analyze", json={"events": [event]}).status_code == 422


def test_analyze_rejects_empty_event_list(client: TestClient) -> None:
    assert client.post("/analyze", json={"events": []}).status_code == 422


def test_analyze_rejects_non_chronological_events(client: TestClient) -> None:
    events = [
        valid_event(timestamp="2026-09-01T10:00:05Z"),
        valid_event(timestamp="2026-09-01T10:00:00Z"),
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 422
    assert "chronological" in response.json()["detail"]


def test_analyze_rejects_naive_timestamp(client: TestClient) -> None:
    event = valid_event(timestamp="2026-09-01T10:00:00")

    response = client.post("/analyze", json={"events": [event]})

    assert response.status_code == 422
    assert "timezone" in response.json()["detail"]


def test_failure_burst_response_contains_r001(
    client: TestClient,
) -> None:
    events = generate_failure_burst(attempts=6, start_time=START_TIME)
    payload = [event.model_dump(mode="json") for event in events]

    response = client.post("/analyze", json={"events": payload})

    rule_ids = {
        match["rule_id"]
        for match in response.json()["assessments"][-1]["rule_matches"]
    }
    assert "R001" in rule_ids


def test_multi_account_response_contains_r002(
    client: TestClient,
) -> None:
    events = generate_multi_account_activity(
        user_ids=["user-a", "user-b", "user-c", "user-d"],
        start_time=START_TIME,
    )
    payload = [event.model_dump(mode="json") for event in events]

    response = client.post("/analyze", json={"events": payload})

    rule_ids = {
        match["rule_id"]
        for match in response.json()["assessments"][-1]["rule_matches"]
    }
    assert "R002" in rule_ids


def test_analyze_reuses_same_model_across_requests(
    trained_model: IsolationForest,
) -> None:
    api = create_app(model=trained_model)
    client = TestClient(api)
    original_model = api.state.model

    client.post("/analyze", json={"events": [valid_event()]})
    client.post("/analyze", json={"events": [valid_event()]})

    assert api.state.model is original_model
    assert api.state.model is trained_model


def test_openapi_contains_health_and_analyze_paths(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert {"/health", "/analyze"} <= response.json()["paths"].keys()
