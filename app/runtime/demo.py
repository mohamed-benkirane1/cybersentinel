"""Launch the CyberSentinel API and dashboard for a local demonstration."""

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class DemoRuntimeConfig:
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8501


def validate_runtime_config(config: DemoRuntimeConfig) -> None:
    """Validate hosts and ports used by the local demonstration runtime."""
    if not config.api_host.strip():
        raise ValueError("api_host must not be empty")
    if not config.dashboard_host.strip():
        raise ValueError("dashboard_host must not be empty")
    if not 1 <= config.api_port <= 65535:
        raise ValueError("api_port must be between 1 and 65535")
    if not 1 <= config.dashboard_port <= 65535:
        raise ValueError("dashboard_port must be between 1 and 65535")
    if config.api_port == config.dashboard_port:
        raise ValueError("api_port and dashboard_port must be different")


def build_api_command(config: DemoRuntimeConfig) -> list[str]:
    """Build the Uvicorn command using the current Python interpreter."""
    return [
        sys.executable,
        "-m",
        "uvicorn",
        "app.api.main:app",
        "--host",
        config.api_host,
        "--port",
        str(config.api_port),
    ]


def build_dashboard_command(config: DemoRuntimeConfig) -> list[str]:
    """Build the Streamlit command using the current Python interpreter."""
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app/dashboard/main.py",
        "--server.address",
        config.dashboard_host,
        "--server.port",
        str(config.dashboard_port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]


def _wait_for_api(
    process: subprocess.Popen[bytes],
    api_base_url: str,
    *,
    timeout: float = 15.0,
    poll_interval: float = 0.1,
) -> None:
    """Wait for a healthy API response within a bounded interval."""
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=0.5) as client:
        while time.monotonic() < deadline:
            return_code = process.poll()
            if return_code is not None:
                raise RuntimeError(
                    "CyberSentinel API exited before becoming ready "
                    f"(exit code {return_code})"
                )

            try:
                response = client.get(f"{api_base_url}/health")
                response.raise_for_status()
                health = response.json()
            except (httpx.HTTPError, ValueError):
                time.sleep(poll_interval)
                continue

            if (
                isinstance(health, dict)
                and health.get("status") == "ok"
                and health.get("model_ready") is True
            ):
                return
            time.sleep(poll_interval)

    raise RuntimeError(
        f"CyberSentinel API did not become ready within {timeout:g} seconds"
    )


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate a child process and kill it only when graceful exit times out."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def start_demo(config: DemoRuntimeConfig | None = None) -> int:
    """Start the API followed by the dashboard and supervise both processes."""
    runtime_config = config if config is not None else DemoRuntimeConfig()
    validate_runtime_config(runtime_config)

    api_base_url = (
        f"http://{runtime_config.api_host}:{runtime_config.api_port}"
    )
    dashboard_url = (
        f"http://{runtime_config.dashboard_host}:{runtime_config.dashboard_port}"
    )

    try:
        api_process = subprocess.Popen(build_api_command(runtime_config))
    except OSError as exc:
        raise RuntimeError("Unable to start the CyberSentinel API") from exc

    dashboard_process: subprocess.Popen[bytes] | None = None
    try:
        _wait_for_api(api_process, api_base_url)
        print(f"CyberSentinel API ready at {api_base_url}", flush=True)

        dashboard_environment = os.environ.copy()
        dashboard_environment["CYBERSENTINEL_API_BASE_URL"] = api_base_url
        try:
            dashboard_process = subprocess.Popen(
                build_dashboard_command(runtime_config),
                env=dashboard_environment,
            )
        except OSError as exc:
            raise RuntimeError("Unable to start the CyberSentinel dashboard") from exc

        if dashboard_process.poll() is not None:
            raise RuntimeError("CyberSentinel dashboard exited during startup")

        print(
            f"CyberSentinel dashboard available at {dashboard_url}",
            flush=True,
        )

        while True:
            api_return_code = api_process.poll()
            if api_return_code is not None:
                raise RuntimeError(
                    "CyberSentinel API exited unexpectedly "
                    f"(exit code {api_return_code})"
                )

            dashboard_return_code = dashboard_process.poll()
            if dashboard_return_code is not None:
                if dashboard_return_code != 0:
                    raise RuntimeError(
                        "CyberSentinel dashboard exited unexpectedly "
                        f"(exit code {dashboard_return_code})"
                    )
                return 0
            time.sleep(0.2)
    except KeyboardInterrupt:
        return 0
    finally:
        if dashboard_process is not None:
            _stop_process(dashboard_process)
        _stop_process(api_process)


def main() -> int:
    """Parse CLI options and run the local demonstration."""
    defaults = DemoRuntimeConfig()
    parser = argparse.ArgumentParser(description="Run the CyberSentinel local demo")
    parser.add_argument("--api-host", default=defaults.api_host)
    parser.add_argument("--api-port", type=int, default=defaults.api_port)
    parser.add_argument("--dashboard-host", default=defaults.dashboard_host)
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=defaults.dashboard_port,
    )
    arguments = parser.parse_args()
    return start_demo(
        DemoRuntimeConfig(
            api_host=arguments.api_host,
            api_port=arguments.api_port,
            dashboard_host=arguments.dashboard_host,
            dashboard_port=arguments.dashboard_port,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
