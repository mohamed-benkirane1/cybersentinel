"""Compute temporal features for authentication events."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models import AuthenticationEvent


@dataclass(frozen=True)
class AuthEventFeatures:
    """Temporal features associated with one authentication event."""

    event: AuthenticationEvent
    attempts_5m: int
    failed_attempts_5m: int
    unique_users_per_ip_5m: int
    unique_ips_per_user_30m: int


def compute_auth_features(
    events: list[AuthenticationEvent],
) -> list[AuthEventFeatures]:
    """Compute past-only temporal features in chronological input order."""
    user_events_5m: defaultdict[str, deque[AuthenticationEvent]] = defaultdict(
        deque
    )
    ip_events_5m: defaultdict[str, deque[AuthenticationEvent]] = defaultdict(deque)
    user_events_30m: defaultdict[str, deque[AuthenticationEvent]] = defaultdict(
        deque
    )
    features: list[AuthEventFeatures] = []
    previous_timestamp: datetime | None = None

    for event in events:
        timestamp = event.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("event timestamps must include timezone information")
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise ValueError("events must be in chronological order")
        previous_timestamp = timestamp

        five_minute_cutoff = timestamp - timedelta(minutes=5)
        recent_user_events = user_events_5m[event.user_id]
        while recent_user_events and recent_user_events[0].timestamp < five_minute_cutoff:
            recent_user_events.popleft()
        recent_user_events.append(event)

        recent_ip_events = ip_events_5m[str(event.source_ip)]
        while recent_ip_events and recent_ip_events[0].timestamp < five_minute_cutoff:
            recent_ip_events.popleft()
        recent_ip_events.append(event)

        thirty_minute_cutoff = timestamp - timedelta(minutes=30)
        recent_user_events_30m = user_events_30m[event.user_id]
        while (
            recent_user_events_30m
            and recent_user_events_30m[0].timestamp < thirty_minute_cutoff
        ):
            recent_user_events_30m.popleft()
        recent_user_events_30m.append(event)

        features.append(
            AuthEventFeatures(
                event=event,
                attempts_5m=len(recent_user_events),
                failed_attempts_5m=sum(
                    recent_event.result == "failure"
                    for recent_event in recent_user_events
                ),
                unique_users_per_ip_5m=len(
                    {recent_event.user_id for recent_event in recent_ip_events}
                ),
                unique_ips_per_user_30m=len(
                    {
                        recent_event.source_ip
                        for recent_event in recent_user_events_30m
                    }
                ),
            )
        )

    return features
