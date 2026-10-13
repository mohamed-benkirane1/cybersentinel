"""Streamlit dashboard API client utilities."""

from .client import DashboardAPIError, analyze_events, get_health

__all__ = ["DashboardAPIError", "analyze_events", "get_health"]
