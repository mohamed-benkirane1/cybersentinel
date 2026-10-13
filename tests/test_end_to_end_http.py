import socket
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone

import httpx
import pytest
import uvicorn

from app.api import create_app
from app.dashboard import DashboardAPIError, analyze_events, get_health
from app.data import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)
from app.features import compute_auth_features
from app.ml import train_isolation_forest


START_TIME = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
ASSESSMENT_KEYS = {
    "risk_score",
    "risk_level",
    "confidence",
    "ml_anomaly_score",
    "ml_is_anomaly",
    "rule_matches",
}


@pytest.fixture(scope="module")
def live_api_server() -> Iterator[str]:
    training_events = generate_normal_events(80, seed=1101)
    training_records = compute_auth_features(training_events)
    model = train_isolation_forest(training_records, random_state=42)
    api = create_app(model=model)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    port = server_socket.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(
        api,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [server_socket]},
        daemon=True,
    )
    thread.start()

    try:
        deadline = time.monotonic() + 10.0
        with httpx.Client(timeout=0.5) as readiness_client:
            while time.monotonic() < deadline:
                if not thread.is_alive():
                    pytest.fail("Uvicorn stopped before the API became ready")
                try:
                    health = get_health(base_url, client=readiness_client)
                except DashboardAPIError:
                    time.sleep(0.05)
                    continue
                if health.get("status") == "ok":
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Uvicorn did not become ready within 10 seconds")

        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=5.0)
        server_socket.close()
        if thread.is_alive():
            pytest.fail("Uvicorn thread did not stop cleanly")


def test_health_through_real_http(live_api_server: str) -> None:
    health = get_health(live_api_server)

    assert health["status"] == "ok"
    assert health["service"] == "cybersentinel"
    assert health["model_ready"] is True
    assert health["prototype"] is True


def test_normal_event_analysis_through_real_http(live_api_server: str) -> None:
    events = generate_normal_events(5, seed=1102)

    result = analyze_events(live_api_server, events)

    assert result["assessment_count"] == len(events)
    assessments = result["assessments"]
    assert len(assessments) == len(events)
    assert [assessment["user_id"] for assessment in assessments] == [
        event.user_id for event in events
    ]
    assert all(ASSESSMENT_KEYS <= assessment.keys() for assessment in assessments)


def test_failure_burst_triggers_r001_through_real_http(
    live_api_server: str,
) -> None:
    events = generate_failure_burst(attempts=6, start_time=START_TIME)

    result = analyze_events(live_api_server, events)

    rule_ids = {
        match["rule_id"]
        for match in result["assessments"][-1]["rule_matches"]
    }
    assert "R001" in rule_ids


def test_multi_account_activity_triggers_r002_through_real_http(
    live_api_server: str,
) -> None:
    events = generate_multi_account_activity(
        user_ids=[
            "e2e-user-a",
            "e2e-user-b",
            "e2e-user-c",
            "e2e-user-d",
        ],
        start_time=START_TIME,
    )

    result = analyze_events(live_api_server, events)

    rule_ids = {
        match["rule_id"]
        for match in result["assessments"][-1]["rule_matches"]
    }
    assert "R002" in rule_ids


def test_model_lifecycle_across_real_http_requests(
    live_api_server: str,
) -> None:
    events = generate_normal_events(3, seed=1103)

    for _ in range(3):
        result = analyze_events(live_api_server, events)
        assert result["assessment_count"] == len(events)

    health = get_health(live_api_server)
    assert health["status"] == "ok"
    assert health["model_ready"] is True


def test_api_validation_error_becomes_dashboard_error(
    live_api_server: str,
) -> None:
    events = list(reversed(generate_normal_events(2, seed=1104)))

    with pytest.raises(DashboardAPIError):
        analyze_events(live_api_server, events)
