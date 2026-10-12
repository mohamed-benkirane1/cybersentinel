"""Synthetic data generation utilities."""

from .synthetic import (
    generate_failure_burst,
    generate_multi_account_activity,
    generate_normal_events,
)

__all__ = [
    "generate_failure_burst",
    "generate_multi_account_activity",
    "generate_normal_events",
]
