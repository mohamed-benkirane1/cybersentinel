import importlib
import json
import sys
from datetime import datetime, timezone

import httpx
import pytest

from app.dashboard import DashboardAPIError, analyze_events, get_health
from app.dashboard.client import normalize_api_base_url
from app.models import AuthenticationEvent


def make_event() -> AuthenticationEvent:
    return AuthenticationEvent(
        timestamp=datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc),
        user_id="demo-user",
        source_ip="192.0.2.10",
        result="success",
        service="vpn",
    )


def make_client(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler)


def test_normalize_api_base_url_strips_whitespace() -> None:
    assert normalize_api_base_url("  http://api.test  ") == "http://api.test"


def test_normalize_api_base_url_removes_trailing_slashes() -> None:
    assert normalize_api_base_url("http://api.test///") == "http://api.test"


@pytest.mark.parametrize("value", ["", "   ", "///"])
def test_normalize_api_base_url_rejects_empty_value(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_api_base_url(value)


def test_get_health_calls_health_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/health"
        return httpx.Response(200, json={"status": "ok"})

    with make_client(httpx.MockTransport(handler)) as client:
        get_health("http://api.test", client=client)


def test_get_health_returns_expected_json() -> None:
    expected = {"status": "ok", "model_ready": True}
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=expected)
    )

    with make_client(transport) as client:
        assert get_health("http://api.test", client=client) == expected


def test_get_health_transforms_http_error() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(503, json={"detail": "unavailable"})
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            get_health("http://api.test", client=client)


def test_get_health_rejects_non_dict_response() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=["unexpected"])
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            get_health("http://api.test", client=client)


def test_analyze_events_calls_analyze_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/analyze"
        return httpx.Response(
            200,
            json={"assessment_count": 0, "assessments": []},
        )

    with make_client(httpx.MockTransport(handler)) as client:
        analyze_events("http://api.test", [make_event()], client=client)


def test_analyze_events_serializes_authentication_events() -> None:
    event = make_event()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload == {"events": [event.model_dump(mode="json")]}
        return httpx.Response(
            200,
            json={"assessment_count": 1, "assessments": [{}]},
        )

    with make_client(httpx.MockTransport(handler)) as client:
        analyze_events("http://api.test", [event], client=client)


def test_analyze_events_returns_assessment_count() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"assessment_count": 1, "assessments": [{}]},
        )
    )

    with make_client(transport) as client:
        result = analyze_events("http://api.test", [make_event()], client=client)

    assert result["assessment_count"] == 1


def test_analyze_events_preserves_assessments() -> None:
    assessments = [{"user_id": "demo-user", "risk_score": 40}]
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"assessment_count": 1, "assessments": assessments},
        )
    )

    with make_client(transport) as client:
        result = analyze_events("http://api.test", [make_event()], client=client)

    assert result["assessments"] == assessments


def test_analyze_events_transforms_http_error() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(422, json={"detail": "invalid"})
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            analyze_events("http://api.test", [make_event()], client=client)


def test_analyze_events_rejects_non_dict_response() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=[])
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            analyze_events("http://api.test", [make_event()], client=client)


def test_analyze_events_rejects_missing_assessment_count() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"assessments": []})
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            analyze_events("http://api.test", [make_event()], client=client)


def test_analyze_events_rejects_missing_assessments() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"assessment_count": 0})
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            analyze_events("http://api.test", [make_event()], client=client)


def test_analyze_events_rejects_non_list_assessments() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"assessment_count": 0, "assessments": {}},
        )
    )

    with make_client(transport) as client:
        with pytest.raises(DashboardAPIError):
            analyze_events("http://api.test", [make_event()], client=client)


def test_injected_client_remains_open_after_call() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"status": "ok"})
    )
    client = make_client(transport)

    get_health("http://api.test", client=client)

    assert client.is_closed is False
    assert get_health("http://api.test", client=client)["status"] == "ok"
    client.close()


def test_importing_dashboard_main_does_not_make_network_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_request(*args: object, **kwargs: object) -> None:
        raise AssertionError("dashboard import attempted a network request")

    monkeypatch.setattr(httpx.Client, "request", fail_request)
    sys.modules.pop("app.dashboard.main", None)

    importlib.import_module("app.dashboard.main")
