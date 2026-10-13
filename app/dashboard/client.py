"""HTTP client for the CyberSentinel FastAPI service."""

import httpx

from app.models import AuthenticationEvent


class DashboardAPIError(RuntimeError):
    pass


def normalize_api_base_url(api_base_url: str) -> str:
    """Return a non-empty API URL without surrounding or trailing whitespace."""
    normalized_url = api_base_url.strip().rstrip("/")
    if not normalized_url:
        raise ValueError("api_base_url must not be empty")
    return normalized_url


def _request_json(
    method: str,
    url: str,
    *,
    client: httpx.Client | None,
    json: dict[str, object] | None = None,
) -> object:
    try:
        if client is None:
            with httpx.Client(timeout=10.0) as local_client:
                response = local_client.request(method, url, json=json)
        else:
            response = client.request(method, url, json=json)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise DashboardAPIError(f"CyberSentinel API request failed: {exc}") from exc

    try:
        return response.json()
    except ValueError as exc:
        raise DashboardAPIError("CyberSentinel API returned invalid JSON") from exc


def get_health(
    api_base_url: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, object]:
    """Return the API health response."""
    base_url = normalize_api_base_url(api_base_url)
    payload = _request_json("GET", f"{base_url}/health", client=client)
    if not isinstance(payload, dict):
        raise DashboardAPIError("CyberSentinel health response must be an object")
    return payload


def analyze_events(
    api_base_url: str,
    events: list[AuthenticationEvent],
    *,
    client: httpx.Client | None = None,
) -> dict[str, object]:
    """Send authentication events to the API and return its assessments."""
    base_url = normalize_api_base_url(api_base_url)
    payload = _request_json(
        "POST",
        f"{base_url}/analyze",
        client=client,
        json={"events": [event.model_dump(mode="json") for event in events]},
    )
    if not isinstance(payload, dict):
        raise DashboardAPIError("CyberSentinel analyze response must be an object")
    if "assessment_count" not in payload:
        raise DashboardAPIError("Analyze response is missing assessment_count")
    if "assessments" not in payload:
        raise DashboardAPIError("Analyze response is missing assessments")
    if not isinstance(payload["assessments"], list):
        raise DashboardAPIError("Analyze response assessments must be a list")
    return payload
