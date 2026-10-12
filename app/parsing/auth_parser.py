"""Parse raw authentication data into validated events."""

from app.models import AuthenticationEvent


def parse_auth_event(raw_event: dict[str, object]) -> AuthenticationEvent:
    """Return a validated authentication event from raw data."""
    return AuthenticationEvent.model_validate(raw_event)


def parse_auth_events(
    raw_events: list[dict[str, object]],
) -> list[AuthenticationEvent]:
    """Return validated authentication events in their input order."""
    return [parse_auth_event(raw_event) for raw_event in raw_events]
