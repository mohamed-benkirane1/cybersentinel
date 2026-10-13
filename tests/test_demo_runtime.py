import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

import app.dashboard.main as dashboard_main
import app.runtime.demo as runtime
from app.runtime import (
    DemoRuntimeConfig,
    build_api_command,
    build_dashboard_command,
)


def test_runtime_config_has_expected_defaults() -> None:
    assert DemoRuntimeConfig() == DemoRuntimeConfig(
        api_host="127.0.0.1",
        api_port=8000,
        dashboard_host="127.0.0.1",
        dashboard_port=8501,
    )


def test_empty_api_host_is_rejected() -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(DemoRuntimeConfig(api_host="   "))


def test_empty_dashboard_host_is_rejected() -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(DemoRuntimeConfig(dashboard_host=""))


def test_zero_api_port_is_rejected() -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(DemoRuntimeConfig(api_port=0))


def test_api_port_above_maximum_is_rejected() -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(DemoRuntimeConfig(api_port=65536))


@pytest.mark.parametrize("port", [0, 65536])
def test_invalid_dashboard_port_is_rejected(port: int) -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(DemoRuntimeConfig(dashboard_port=port))


def test_identical_ports_are_rejected() -> None:
    with pytest.raises(ValueError):
        runtime.validate_runtime_config(
            DemoRuntimeConfig(api_port=9000, dashboard_port=9000)
        )


def test_api_command_uses_current_python() -> None:
    assert build_api_command(DemoRuntimeConfig())[0] == sys.executable


def test_api_command_contains_application() -> None:
    assert "app.api.main:app" in build_api_command(DemoRuntimeConfig())


def test_api_command_contains_configured_host_and_port() -> None:
    config = DemoRuntimeConfig(api_host="127.0.0.2", api_port=9100)
    command = build_api_command(config)

    assert command[command.index("--host") + 1] == "127.0.0.2"
    assert command[command.index("--port") + 1] == "9100"


def test_dashboard_command_uses_current_python() -> None:
    assert build_dashboard_command(DemoRuntimeConfig())[0] == sys.executable


def test_dashboard_command_points_to_dashboard_main() -> None:
    command = build_dashboard_command(DemoRuntimeConfig())

    assert command[3:5] == ["run", "app/dashboard/main.py"]


def test_dashboard_command_contains_configured_host_and_port() -> None:
    config = DemoRuntimeConfig(
        dashboard_host="127.0.0.3",
        dashboard_port=9200,
    )
    command = build_dashboard_command(config)

    assert command[command.index("--server.address") + 1] == "127.0.0.3"
    assert command[command.index("--server.port") + 1] == "9200"


def test_dashboard_command_enables_headless_mode() -> None:
    command = build_dashboard_command(DemoRuntimeConfig())

    assert command[command.index("--server.headless") + 1] == "true"


def test_dashboard_command_disables_usage_statistics() -> None:
    command = build_dashboard_command(DemoRuntimeConfig())

    assert command[command.index("--browser.gatherUsageStats") + 1] == "false"


def _successful_processes() -> tuple[Mock, Mock]:
    api_process = Mock(name="api_process")
    api_process.poll.return_value = None
    dashboard_process = Mock(name="dashboard_process")
    dashboard_process.poll.side_effect = [None, 0]
    return api_process, dashboard_process


def test_dashboard_environment_contains_api_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = DemoRuntimeConfig(api_host="127.0.0.5", api_port=9300)
    api_process, dashboard_process = _successful_processes()
    popen = Mock(side_effect=[api_process, dashboard_process])
    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    monkeypatch.setattr(runtime, "_wait_for_api", Mock())
    monkeypatch.setattr(runtime, "_stop_process", Mock())

    assert runtime.start_demo(config) == 0

    dashboard_environment = popen.call_args_list[1].kwargs["env"]
    assert (
        dashboard_environment["CYBERSENTINEL_API_BASE_URL"]
        == "http://127.0.0.5:9300"
    )


def test_api_starts_before_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    api_process, dashboard_process = _successful_processes()

    def fake_popen(command: list[str], **kwargs: object) -> Mock:
        process = api_process if "uvicorn" in command else dashboard_process
        events.append("api started" if process is api_process else "dashboard started")
        return process

    def fake_wait(process: Mock, api_base_url: str) -> None:
        events.append("api ready")

    monkeypatch.setattr(runtime.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(runtime, "_wait_for_api", fake_wait)
    monkeypatch.setattr(runtime, "_stop_process", Mock())

    runtime.start_demo()

    assert events == ["api started", "api ready", "dashboard started"]


def test_dashboard_is_not_started_when_api_readiness_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_process = Mock()
    popen = Mock(return_value=api_process)
    monkeypatch.setattr(runtime.subprocess, "Popen", popen)
    monkeypatch.setattr(
        runtime,
        "_wait_for_api",
        Mock(side_effect=RuntimeError("API startup failed")),
    )
    monkeypatch.setattr(runtime, "_stop_process", Mock())

    with pytest.raises(RuntimeError, match="API startup failed"):
        runtime.start_demo()

    popen.assert_called_once()


def test_api_is_cleaned_when_readiness_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_process = Mock()
    stop_process = Mock()
    monkeypatch.setattr(runtime.subprocess, "Popen", Mock(return_value=api_process))
    monkeypatch.setattr(
        runtime,
        "_wait_for_api",
        Mock(side_effect=RuntimeError("API startup failed")),
    )
    monkeypatch.setattr(runtime, "_stop_process", stop_process)

    with pytest.raises(RuntimeError):
        runtime.start_demo()

    stop_process.assert_called_once_with(api_process)


def test_dashboard_immediate_failure_cleans_both_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_process = Mock(name="api_process")
    dashboard_process = Mock(name="dashboard_process")
    dashboard_process.poll.return_value = 1
    stop_process = Mock()
    monkeypatch.setattr(
        runtime.subprocess,
        "Popen",
        Mock(side_effect=[api_process, dashboard_process]),
    )
    monkeypatch.setattr(runtime, "_wait_for_api", Mock())
    monkeypatch.setattr(runtime, "_stop_process", stop_process)

    with pytest.raises(RuntimeError, match="dashboard exited during startup"):
        runtime.start_demo()

    assert stop_process.call_args_list == [
        call(dashboard_process),
        call(api_process),
    ]


def test_keyboard_interrupt_cleans_dashboard_then_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_process = Mock(name="api_process")
    api_process.poll.return_value = None
    dashboard_process = Mock(name="dashboard_process")
    dashboard_process.poll.return_value = None
    stop_process = Mock()
    monkeypatch.setattr(
        runtime.subprocess,
        "Popen",
        Mock(side_effect=[api_process, dashboard_process]),
    )
    monkeypatch.setattr(runtime, "_wait_for_api", Mock())
    monkeypatch.setattr(runtime, "_stop_process", stop_process)
    monkeypatch.setattr(
        runtime.time,
        "sleep",
        Mock(side_effect=KeyboardInterrupt),
    )

    assert runtime.start_demo() == 0
    assert stop_process.call_args_list == [
        call(dashboard_process),
        call(api_process),
    ]


def test_process_requiring_kill_is_finally_stopped() -> None:
    process = Mock()
    process.poll.return_value = None
    process.wait.side_effect = [
        subprocess.TimeoutExpired(cmd="demo", timeout=5.0),
        0,
    ]

    runtime._stop_process(process)

    process.terminate.assert_called_once_with()
    process.kill.assert_called_once_with()
    assert process.wait.call_args_list == [call(timeout=5.0), call()]


def test_main_passes_cli_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    start_demo = Mock(return_value=0)
    monkeypatch.setattr(runtime, "start_demo", start_demo)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo",
            "--api-host",
            "127.0.0.7",
            "--api-port",
            "9400",
            "--dashboard-host",
            "127.0.0.8",
            "--dashboard-port",
            "9500",
        ],
    )

    assert runtime.main() == 0
    start_demo.assert_called_once_with(
        DemoRuntimeConfig(
            api_host="127.0.0.7",
            api_port=9400,
            dashboard_host="127.0.0.8",
            dashboard_port=9500,
        )
    )


def test_dashboard_uses_api_url_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    class SidebarStub:
        def text_input(self, label: str, *, value: str) -> str:
            captured["value"] = value
            return value

        def button(self, label: str) -> bool:
            return False

    streamlit_stub = SimpleNamespace(
        sidebar=SidebarStub(),
        set_page_config=lambda **kwargs: None,
        title=lambda *args, **kwargs: None,
        subheader=lambda *args, **kwargs: None,
        caption=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        selectbox=lambda label, options: options[0],
        dataframe=lambda *args, **kwargs: None,
        button=lambda *args, **kwargs: False,
    )
    monkeypatch.setenv(
        "CYBERSENTINEL_API_BASE_URL",
        "http://127.0.0.1:9999",
    )
    monkeypatch.setattr(dashboard_main, "st", streamlit_stub)

    dashboard_main.render_dashboard()

    assert captured["value"] == "http://127.0.0.1:9999"


def test_dashboard_handles_empty_api_url_when_checking_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors: list[str] = []

    class SidebarStub:
        def text_input(self, label: str, *, value: str) -> str:
            return ""

        def button(self, label: str) -> bool:
            return True

        def error(self, message: str) -> None:
            errors.append(message)

    streamlit_stub = SimpleNamespace(
        sidebar=SidebarStub(),
        set_page_config=lambda **kwargs: None,
        title=lambda *args, **kwargs: None,
        subheader=lambda *args, **kwargs: None,
        caption=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        selectbox=lambda label, options: options[0],
        dataframe=lambda *args, **kwargs: None,
        button=lambda *args, **kwargs: False,
    )
    monkeypatch.setattr(dashboard_main, "st", streamlit_stub)

    dashboard_main.render_dashboard()

    assert len(errors) == 1
    assert "api_base_url must not be empty" in errors[0]


def test_dashboard_handles_empty_api_url_when_analyzing_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors: list[str] = []

    class SidebarStub:
        def text_input(self, label: str, *, value: str) -> str:
            return ""

        def button(self, label: str) -> bool:
            return False

    streamlit_stub = SimpleNamespace(
        sidebar=SidebarStub(),
        set_page_config=lambda **kwargs: None,
        title=lambda *args, **kwargs: None,
        subheader=lambda *args, **kwargs: None,
        caption=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        selectbox=lambda label, options: options[0],
        dataframe=lambda *args, **kwargs: None,
        button=lambda *args, **kwargs: True,
        error=lambda message: errors.append(message),
    )
    monkeypatch.setattr(dashboard_main, "st", streamlit_stub)

    dashboard_main.render_dashboard()

    assert len(errors) == 1
    assert "api_base_url must not be empty" in errors[0]
