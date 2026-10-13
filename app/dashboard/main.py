"""Streamlit dashboard for the CyberSentinel FastAPI service."""

from datetime import datetime, timezone

import streamlit as st

from app.dashboard import DashboardAPIError, analyze_events, get_health
from app.dashboard.demo_data import DEMO_SCENARIOS, build_demo_events


def _render_assessment_results(result: dict[str, object]) -> None:
    assessments = result["assessments"]
    if not isinstance(assessments, list):
        return

    high_risk = sum(
        assessment.get("risk_level") == "high"
        for assessment in assessments
        if isinstance(assessment, dict)
    )
    medium_risk = sum(
        assessment.get("risk_level") == "medium"
        for assessment in assessments
        if isinstance(assessment, dict)
    )
    low_risk = sum(
        assessment.get("risk_level") == "low"
        for assessment in assessments
        if isinstance(assessment, dict)
    )
    ml_anomalies = sum(
        assessment.get("ml_is_anomaly") is True
        for assessment in assessments
        if isinstance(assessment, dict)
    )

    metric_columns = st.columns(5)
    metric_columns[0].metric("Events analyzed", result["assessment_count"])
    metric_columns[1].metric("High risk", high_risk)
    metric_columns[2].metric("Medium risk", medium_risk)
    metric_columns[3].metric("Low risk", low_risk)
    metric_columns[4].metric("ML anomalies", ml_anomalies)

    assessment_rows = [
        {
            "timestamp": assessment.get("timestamp"),
            "user_id": assessment.get("user_id"),
            "source_ip": assessment.get("source_ip"),
            "result": assessment.get("result"),
            "risk_score": assessment.get("risk_score"),
            "risk_level": assessment.get("risk_level"),
            "confidence": assessment.get("confidence"),
            "ml_is_anomaly": assessment.get("ml_is_anomaly"),
            "ml_anomaly_score": assessment.get("ml_anomaly_score"),
        }
        for assessment in assessments
        if isinstance(assessment, dict)
    ]
    st.subheader("Assessments")
    st.dataframe(assessment_rows, use_container_width=True, hide_index=True)

    st.subheader("Assessment details")
    for assessment in assessments:
        if not isinstance(assessment, dict):
            continue
        title = (
            f"{assessment.get('user_id')} — {assessment.get('risk_level')} — "
            f"score {assessment.get('risk_score')}"
        )
        with st.expander(title):
            st.write(
                {
                    "timestamp": assessment.get("timestamp"),
                    "source_ip": assessment.get("source_ip"),
                    "service": assessment.get("service"),
                    "attempts_5m": assessment.get("attempts_5m"),
                    "failed_attempts_5m": assessment.get("failed_attempts_5m"),
                    "unique_users_per_ip_5m": assessment.get(
                        "unique_users_per_ip_5m"
                    ),
                    "unique_ips_per_user_30m": assessment.get(
                        "unique_ips_per_user_30m"
                    ),
                    "heuristic priority score": assessment.get("risk_score"),
                    "risk_level": assessment.get("risk_level"),
                    "signal agreement": assessment.get("confidence"),
                    "relative Isolation Forest anomaly score": assessment.get(
                        "ml_anomaly_score"
                    ),
                    "ML anomaly": assessment.get("ml_is_anomaly"),
                }
            )

            st.markdown("**Reasons**")
            reasons = assessment.get("reasons", [])
            if reasons:
                for reason in reasons:
                    st.write(f"- {reason}")
            else:
                st.write("No elevated signal reason.")

            st.markdown("**Triggered deterministic rules**")
            rule_matches = assessment.get("rule_matches", [])
            if rule_matches:
                for rule in rule_matches:
                    st.write(
                        {
                            "rule_id": rule.get("rule_id"),
                            "severity": rule.get("severity"),
                            "description": rule.get("description"),
                            "evidence": rule.get("evidence"),
                        }
                    )
            else:
                st.write("No deterministic rule triggered.")


def render_dashboard() -> None:
    st.set_page_config(
        page_title="CyberSentinel",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("CyberSentinel")
    st.subheader("AI-Assisted Authentication Log Anomaly Detection")
    st.caption("Academic Blue Team prototype")
    st.info(
        "Anomaly detection does not confirm a cyberattack. Risk scores are "
        "heuristic prioritization signals, and the demo model is trained on "
        "synthetic normal traffic."
    )

    api_base_url = st.sidebar.text_input(
        "API Base URL",
        value="http://127.0.0.1:8000",
    )
    if st.sidebar.button("Check API"):
        try:
            health = get_health(api_base_url)
        except DashboardAPIError as exc:
            st.sidebar.error(str(exc))
        else:
            if health.get("status") == "ok" and health.get("model_ready") is True:
                st.sidebar.success("CyberSentinel API is ready.")
            else:
                st.sidebar.warning("CyberSentinel API is not fully ready.")

    scenario = st.selectbox("Demo scenario", DEMO_SCENARIOS)
    start_time = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
    events = build_demo_events(scenario, start_time=start_time)
    event_rows = [
        {
            "timestamp": event.timestamp,
            "user_id": event.user_id,
            "source_ip": str(event.source_ip),
            "result": event.result,
            "service": event.service,
        }
        for event in events
    ]

    st.subheader("Synthetic event preview")
    st.dataframe(event_rows, use_container_width=True, hide_index=True)

    if st.button("Analyze events", type="primary"):
        try:
            result = analyze_events(api_base_url, events)
        except DashboardAPIError as exc:
            st.error(str(exc))
        else:
            _render_assessment_results(result)


if __name__ == "__main__":
    render_dashboard()
