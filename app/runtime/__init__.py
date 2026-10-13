"""Local CyberSentinel demonstration runtime."""

from importlib import import_module

__all__ = [
    "DemoRuntimeConfig",
    "build_api_command",
    "build_dashboard_command",
    "start_demo",
]


def __getattr__(name: str) -> object:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    demo = import_module(".demo", __name__)
    return getattr(demo, name)
