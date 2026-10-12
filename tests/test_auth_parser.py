from datetime import datetime, timezone
from ipaddress import ip_address

import pytest
from pydantic import ValidationError

from app.parsing import parse_auth_event, parse_auth_events


def valid_raw_event() -> dict[str, object]:
    return {
        "timestamp": "2026-03-01T10:30:00Z",
        "user_id": "user-123",
        "source_ip": "192.0.2.10",
        "result": "success",
        "service": "vpn",
    }


def test_parse_valid_auth_event() -> None:
    event = parse_auth_event(valid_raw_event())

    assert event.timestamp == datetime(2026, 3, 1, 10, 30, tzinfo=timezone.utc)
    assert event.user_id == "user-123"
    assert event.source_ip == ip_address("192.0.2.10")
    assert event.result == "success"
    assert event.service == "vpn"


def test_iso_timestamp_is_converted_to_datetime() -> None:
    event = parse_auth_event(valid_raw_event())

    assert isinstance(event.timestamp, datetime)
    assert event.timestamp == datetime(2026, 3, 1, 10, 30, tzinfo=timezone.utc)


def test_user_id_is_normalized() -> None:
    raw_event = valid_raw_event()
    raw_event["user_id"] = "  user-123  "

    assert parse_auth_event(raw_event).user_id == "user-123"


def test_service_is_normalized() -> None:
    raw_event = valid_raw_event()
    raw_event["service"] = "  vpn  "

    assert parse_auth_event(raw_event).service == "vpn"


@pytest.mark.parametrize("source_ip", ["192.0.2.10", "2001:db8::10"])
def test_valid_ip_address_is_parsed(source_ip: str) -> None:
    raw_event = valid_raw_event()
    raw_event["source_ip"] = source_ip

    assert parse_auth_event(raw_event).source_ip == ip_address(source_ip)


def test_invalid_ip_address_is_rejected() -> None:
    raw_event = valid_raw_event()
    raw_event["source_ip"] = "not-an-ip-address"

    with pytest.raises(ValidationError):
        parse_auth_event(raw_event)


def test_invalid_result_is_rejected() -> None:
    raw_event = valid_raw_event()
    raw_event["result"] = "unknown"

    with pytest.raises(ValidationError):
        parse_auth_event(raw_event)


def test_missing_required_field_is_rejected() -> None:
    raw_event = valid_raw_event()
    del raw_event["user_id"]

    with pytest.raises(ValidationError):
        parse_auth_event(raw_event)


def test_extra_field_is_rejected() -> None:
    raw_event = valid_raw_event()
    raw_event["unexpected"] = "value"

    with pytest.raises(ValidationError):
        parse_auth_event(raw_event)


def test_parse_auth_events_preserves_input_order() -> None:
    first = valid_raw_event()
    first["user_id"] = "user-first"
    second = valid_raw_event()
    second["user_id"] = "user-second"

    events = parse_auth_events([first, second])

    assert [event.user_id for event in events] == ["user-first", "user-second"]


def test_parse_auth_events_returns_empty_list_for_empty_input() -> None:
    assert parse_auth_events([]) == []


def test_parse_auth_events_rejects_batch_with_invalid_event() -> None:
    valid_event = valid_raw_event()
    invalid_event = valid_raw_event()
    invalid_event["source_ip"] = "not-an-ip-address"

    with pytest.raises(ValidationError):
        parse_auth_events([valid_event, invalid_event])
