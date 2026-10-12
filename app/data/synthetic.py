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


def _as_utc(start_time: datetime) -> datetime:
    if start_time.tzinfo is None or start_time.utcoffset() is None:
        raise ValueError("start_time must include timezone information")
    return start_time.astimezone(timezone.utc)


def generate_failure_burst(
    attempts: int,
    start_time: datetime,
    *,
    user_id: str = "synthetic-user-burst",
    source_ip: str = "192.0.2.100",
    service: str = "vpn",
) -> list[AuthenticationEvent]:
    """Return a short burst of failed attempts for one synthetic account."""
    if attempts <= 0:
        raise ValueError("attempts must be greater than zero")

    start_time_utc = _as_utc(start_time)
    return [
        AuthenticationEvent(
            timestamp=start_time_utc + timedelta(seconds=index * 5),
            user_id=user_id,
            source_ip=source_ip,
            result="failure",
            service=service,
        )
        for index in range(attempts)
    ]


def generate_multi_account_activity(
    user_ids: list[str],
    start_time: datetime,
    *,
    source_ip: str = "198.51.100.100",
    service: str = "web_portal",
) -> list[AuthenticationEvent]:
    """Return failed attempts against synthetic accounts from one source IP."""
    if not user_ids:
        raise ValueError("user_ids must not be empty")
    normalized_user_ids = [user_id.strip() for user_id in user_ids]
    if any(not user_id for user_id in normalized_user_ids):
        raise ValueError("user_ids must not contain empty values")
    if len(normalized_user_ids) < 2:
        raise ValueError("user_ids must contain at least two distinct users")
    if len(set(normalized_user_ids)) != len(normalized_user_ids):
        raise ValueError("user_ids must not contain duplicates")

    start_time_utc = _as_utc(start_time)
    return [
        AuthenticationEvent(
            timestamp=start_time_utc + timedelta(seconds=index * 5),
            user_id=user_id,
            source_ip=source_ip,
            result="failure",
            service=service,
        )
        for index, user_id in enumerate(normalized_user_ids)
    ]
