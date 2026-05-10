"""Streamlit dashboard entry point for the DarkShield platform."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from app.db import get_supabase


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
FINDINGS_TABLE = "findings"
REFRESH_SECONDS = 30
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d6d",
    "HIGH": "#ff7b00",
    "MEDIUM": "#ffd166",
    "LOW": "#4cc9f0",
}


st.set_page_config(page_title="DarkShield", page_icon="🛡️", layout="wide")


def inject_styles() -> None:
    """Apply dark-friendly dashboard styling."""
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #12203a 0%, #07111f 45%, #04070d 100%);
            color: #e8f0ff;
        }
        .dashboard-hero {
            padding: 1.25rem 1.5rem;
            border: 1px solid rgba(76, 201, 240, 0.18);
            background: linear-gradient(135deg, rgba(8, 22, 40, 0.94), rgba(18, 37, 61, 0.84));
            border-radius: 18px;
            box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
            margin-bottom: 1rem;
        }
        .dashboard-subtitle {
            color: #96abc9;
            margin-top: 0.35rem;
            font-size: 1rem;
        }
        .metric-card {
            border: 1px solid rgba(255, 255, 255, 0.08);
            background: rgba(7, 17, 31, 0.72);
            border-radius: 16px;
            padding: 0.9rem 1rem;
        }
        .severity-pill {
            display: inline-block;
            padding: 0.25rem 0.7rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.8rem;
            letter-spacing: 0.03em;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def fetch_dashboard_metrics() -> dict[str, Any]:
    """Fetch total findings and severity distribution from Supabase."""
    client = get_supabase()
    metrics = {
        "database_connected": False,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    }

    if client is None:
        LOGGER.error("Supabase client unavailable while loading dashboard metrics.")
        return metrics

    try:
        response = client.table(FINDINGS_TABLE).select("severity", count="exact").execute()
        rows = getattr(response, "data", []) or []
        metrics["database_connected"] = True
        metrics["total_findings"] = int(getattr(response, "count", len(rows)) or len(rows))

        for row in rows:
            severity = str(row.get("severity", "")).upper()
            if severity == "CRITICAL":
                metrics["critical_count"] += 1
            elif severity == "HIGH":
                metrics["high_count"] += 1
            elif severity == "MEDIUM":
                metrics["medium_count"] += 1
            elif severity == "LOW":
                metrics["low_count"] += 1

        LOGGER.info("Loaded dashboard metrics successfully.")
        return metrics
    except Exception as exc:
        LOGGER.exception("Failed to fetch dashboard metrics: %s", exc)
        return metrics


def fetch_recent_findings(limit: int = 10) -> pd.DataFrame:
    """Fetch the most recent findings for preview."""
    client = get_supabase()
    columns = ["severity", "pattern_type", "matched_value", "risk_score", "created_at"]

    if client is None:
        LOGGER.error("Supabase client unavailable while loading recent findings.")
        return pd.DataFrame(columns=columns)

    try:
        response = (
            client.table(FINDINGS_TABLE)
            .select("severity, pattern_type, matched_value, risk_score, created_at")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        dataframe = pd.DataFrame(rows, columns=columns)
        LOGGER.info("Loaded %s recent finding(s).", len(dataframe))
        return dataframe
    except Exception as exc:
        LOGGER.exception("Failed to fetch recent findings: %s", exc)
        return pd.DataFrame(columns=columns)


def severity_badge(severity: str) -> str:
    """Render a styled severity badge."""
    normalized = str(severity or "LOW").upper()
    color = SEVERITY_COLORS.get(normalized, "#7f8ea3")
    return (
        f"<span class='severity-pill' style='background:{color}22; color:{color}; "
        f"border:1px solid {color}55'>{normalized}</span>"
    )


def render_sidebar(metrics: dict[str, Any], last_updated: datetime) -> None:
    """Render dashboard sidebar details."""
    with st.sidebar:
        st.header("System Status")
        connection_text = "Connected" if metrics["database_connected"] else "Disconnected"
        st.write(f"Database connection: `{connection_text}`")
        st.write(f"Total findings: `{metrics['total_findings']}`")
        st.write(f"Last updated: `{last_updated.strftime('%Y-%m-%d %H:%M:%S UTC')}`")
        st.caption("Auto-refresh: every 30 seconds")


def render_header() -> None:
    """Render dashboard hero header."""
    st.markdown(
        """
        <div class="dashboard-hero">
            <h1 style="margin:0; color:#f4f7ff;">DarkShield Threat Intelligence Platform</h1>
            <p class="dashboard-subtitle">
                AI-powered early detection of leaked credentials and exposed assets
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics(metrics: dict[str, Any]) -> None:
    """Render metric cards and severity overview chart."""
    columns = st.columns(5)
    metric_items = [
        ("Total Findings", metrics["total_findings"]),
        ("CRITICAL", metrics["critical_count"]),
        ("HIGH", metrics["high_count"]),
        ("MEDIUM", metrics["medium_count"]),
        ("LOW", metrics["low_count"]),
    ]

    for column, (label, value) in zip(columns, metric_items):
        with column:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.metric(label=label, value=value)
            st.markdown("</div>", unsafe_allow_html=True)

    severity_frame = pd.DataFrame(
        {
            "severity": SEVERITY_ORDER,
            "count": [
                metrics["critical_count"],
                metrics["high_count"],
                metrics["medium_count"],
                metrics["low_count"],
            ],
        }
    )
    chart = px.bar(
        severity_frame,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Findings by Severity",
    )
    chart.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e8f0ff",
        xaxis_title="",
        yaxis_title="Count",
        legend_title="Severity",
    )
    st.plotly_chart(chart, use_container_width=True)


def render_recent_findings(dataframe: pd.DataFrame) -> None:
    """Render the recent findings preview table."""
    st.subheader("Recent Findings")
    if dataframe.empty:
        st.warning("No findings available yet.")
        return

    preview = dataframe.copy()
    preview["severity"] = preview["severity"].apply(severity_badge)
    preview["risk_score"] = preview["risk_score"].fillna(0).astype(int)
    st.markdown(
        preview.to_html(escape=False, index=False),
        unsafe_allow_html=True,
    )


def main() -> None:
    """Render the DarkShield Streamlit dashboard."""
    inject_styles()
    last_updated = datetime.now(timezone.utc)
    metrics = fetch_dashboard_metrics()
    recent_findings = fetch_recent_findings()

    render_sidebar(metrics, last_updated)
    render_header()

    if not metrics["database_connected"]:
        st.error("Unable to connect to Supabase. Check credentials and try again.")

    render_metrics(metrics)
    render_recent_findings(recent_findings)

    st.caption(f"Auto-refreshing every {REFRESH_SECONDS} seconds.")
    st.markdown(
        f"""
        <script>
        setTimeout(function() {{
            window.location.reload();
        }}, {REFRESH_SECONDS * 1000});
        </script>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        LOGGER.exception("Dashboard failed to render: %s", exc)
        st.error(f"Dashboard failed to render: {exc}")
