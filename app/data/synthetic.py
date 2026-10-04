"""Generate reproducible synthetic authentication traffic."""

from datetime import datetime, timedelta, timezone
from random import Random

from app.models import AuthenticationEvent


_USER_IDS = tuple(f"synthetic-user-{index:02d}" for index in range(1, 9))
_SOURCE_IPS = (
    "192.0.2.10",
    "192.0.2.25",
    "198.51.100.15",
    "198.51.100.40",
    "203.0.113.20",
    "203.0.113.55",
    "2001:db8::10",
    "2001:db8::25",
)
_SERVICES = ("vpn", "web_portal", "email")
_START_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _shuffled_cycles(values: tuple[str, ...], count: int, rng: Random) -> list[str]:
    samples: list[str] = []
    while len(samples) < count:
        cycle = list(values)
        rng.shuffle(cycle)
        samples.extend(cycle)
    return samples[:count]


def generate_normal_events(count: int, seed: int = 42) -> list[AuthenticationEvent]:
    """Return chronologically ordered, reproducible normal authentication events."""
    if count <= 0:
        raise ValueError("count must be greater than zero")

    rng = Random(seed)
    user_ids = _shuffled_cycles(_USER_IDS, count, rng)
    source_ips = _shuffled_cycles(_SOURCE_IPS, count, rng)
    services = _shuffled_cycles(_SERVICES, count, rng)

    failure_count = max(1, count // 10) if count >= 3 else 0
    failure_indexes = set(rng.sample(range(count), failure_count))

    events: list[AuthenticationEvent] = []
    timestamp = _START_TIME
    for index in range(count):
        timestamp += timedelta(seconds=rng.randint(15, 180))
        events.append(
            AuthenticationEvent(
                timestamp=timestamp,
                user_id=user_ids[index],
                source_ip=source_ips[index],
                result="failure" if index in failure_indexes else "success",
                service=services[index],
            )
        )

    return events
