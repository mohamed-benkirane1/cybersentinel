from datetime import datetime, timezone
from ipaddress import ip_address

import pytest
from pydantic import ValidationError

from app.models import AuthenticationEvent


def valid_event_data() -> dict[str, object]:
    return {
        "timestamp": datetime(2026, 10, 4, 10, 30, tzinfo=timezone.utc),
        "user_id": "user-123",
        "source_ip": "192.0.2.10",
        "result": "success",
        "service": "vpn",
    }


@pytest.mark.parametrize("source_ip", ["192.0.2.10", "2001:db8::10"])
def test_valid_authentication_event(source_ip: str) -> None:
    data = valid_event_data()
    data["source_ip"] = source_ip

    event = AuthenticationEvent(**data)

    assert event.timestamp == data["timestamp"]
    assert event.user_id == "user-123"
    assert event.source_ip == ip_address(source_ip)
    assert event.result == "success"
    assert event.service == "vpn"


def test_invalid_ip_address_is_rejected() -> None:
    data = valid_event_data()
    data["source_ip"] = "not-an-ip-address"

    with pytest.raises(ValidationError):
        AuthenticationEvent(**data)


def test_invalid_result_is_rejected() -> None:
    data = valid_event_data()
    data["result"] = "unknown"

    with pytest.raises(ValidationError):
        AuthenticationEvent(**data)


@pytest.mark.parametrize("user_id", ["", "   "])
def test_empty_user_id_is_rejected(user_id: str) -> None:
    data = valid_event_data()
    data["user_id"] = user_id

    with pytest.raises(ValidationError):
        AuthenticationEvent(**data)


@pytest.mark.parametrize("service", ["", "   "])
def test_empty_service_is_rejected(service: str) -> None:
    data = valid_event_data()
    data["service"] = service

    with pytest.raises(ValidationError):
        AuthenticationEvent(**data)
