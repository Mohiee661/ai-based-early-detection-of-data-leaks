"""Domain and email threat lookup portal for DarkShield."""

from __future__ import annotations

import logging
import time
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from app.db import get_supabase


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
FINDINGS_TABLE = "findings"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d6d",
    "HIGH": "#ff9e00",
    "MEDIUM": "#ffd166",
    "LOW": "#4caf50",
}


def inject_styles() -> None:
    """Apply page styling for the lookup experience."""
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #10203a 0%, #07111f 50%, #04070d 100%);
            color: #edf3ff;
        }
        .lookup-shell {
            background: rgba(7, 18, 33, 0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 1.2rem 1.35rem;
            margin-bottom: 1rem;
        }
        .status-banner {
            border-radius: 14px;
            padding: 0.95rem 1.05rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Render a colored severity badge."""
    normalized = str(severity or "LOW").upper()
    color = SEVERITY_COLORS.get(normalized, "#94a3b8")
    return (
        f"<span style='display:inline-block;padding:0.2rem 0.7rem;border-radius:999px;"
        f"font-weight:700;background:{color}20;color:{color};border:1px solid {color}50'>"
        f"{normalized}</span>"
    )


def search_findings(query: str) -> pd.DataFrame:
    """Search findings by matched value or context window content."""
    client = get_supabase()
    columns = [
        "severity",
        "pattern_type",
        "matched_value",
        "risk_score",
        "created_at",
        "context_window",
        "raw_page_id",
        "is_reviewed",
    ]

    if client is None:
        LOGGER.error("Supabase client unavailable during lookup.")
        return pd.DataFrame(columns=columns)

    try:
        response = (
            client.table(FINDINGS_TABLE)
            .select(",".join(columns))
            .or_(f"context_window.ilike.%{query}%,matched_value.ilike.%{query}%")
            .order("created_at", desc=False)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        dataframe = pd.DataFrame(rows, columns=columns)
        LOGGER.info("Lookup returned %s finding(s) for query=%s", len(dataframe), query)
        return dataframe
    except Exception as exc:
        LOGGER.exception("Lookup query failed: %s", exc)
        st.error(f"Lookup failed: {exc}")
        return pd.DataFrame(columns=columns)


def summarize_findings(dataframe: pd.DataFrame) -> dict[str, Any]:
    """Build summary metrics for the lookup results."""
    if dataframe.empty:
        return {
            "total_findings": 0,
            "highest_severity": "LOW",
            "average_risk_score": 0.0,
            "first_seen": "N/A",
            "last_seen": "N/A",
            "has_critical": False,
        }

    working = dataframe.copy()
    working["risk_score"] = pd.to_numeric(working["risk_score"], errors="coerce").fillna(0)
    working["created_at"] = pd.to_datetime(working["created_at"], errors="coerce", utc=True)

    severities = working["severity"].fillna("LOW").str.upper()
    highest = max(severities, key=lambda value: SEVERITY_RANK.get(value, 0))
    first_seen = working["created_at"].min()
    last_seen = working["created_at"].max()

    return {
        "total_findings": int(len(working)),
        "highest_severity": highest,
        "average_risk_score": float(round(working["risk_score"].mean(), 2)),
        "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(first_seen) else "N/A",
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(last_seen) else "N/A",
        "has_critical": "CRITICAL" in set(severities.tolist()),
    }


def render_status_banner(has_critical: bool) -> None:
    """Render a critical or non-critical status banner."""
    if has_critical:
        st.markdown(
            "<div class='status-banner' style='background:#5b102055;color:#ff9db1;border:1px solid #ff4d6d55'>"
            "⚠ Active breach indicators found"
            "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div class='status-banner' style='background:#0f302055;color:#9ef7ba;border:1px solid #4caf5055'>"
            "✓ No critical indicators detected"
            "</div>",
            unsafe_allow_html=True,
        )


def render_summary(summary: dict[str, Any]) -> None:
    """Render summary metrics."""
    columns = st.columns(5)
    metric_values = [
        ("Total Findings", summary["total_findings"]),
        ("Highest Severity", summary["highest_severity"]),
        ("Average Risk Score", summary["average_risk_score"]),
        ("First Seen", summary["first_seen"]),
        ("Last Seen", summary["last_seen"]),
    ]
    for column, (label, value) in zip(columns, metric_values):
        with column:
            st.metric(label=label, value=value)


def render_results_table(dataframe: pd.DataFrame) -> None:
    """Render the findings table."""
    if dataframe.empty:
        st.info("No findings matched the current lookup.")
        return

    preview = dataframe.copy()
    preview["severity"] = preview["severity"].apply(severity_badge)
    st.markdown(preview.to_html(escape=False, index=False), unsafe_allow_html=True)


def render_timeline(dataframe: pd.DataFrame) -> None:
    """Render a findings-over-time chart."""
    if dataframe.empty:
        return

    timeline = dataframe.copy()
    timeline["created_at"] = pd.to_datetime(timeline["created_at"], errors="coerce", utc=True)
    timeline = timeline.dropna(subset=["created_at"])
    if timeline.empty:
        return

    timeline["date"] = timeline["created_at"].dt.floor("D")
    grouped = timeline.groupby("date").size().reset_index(name="findings")

    figure = px.line(
        grouped,
        x="date",
        y="findings",
        markers=True,
        title="Findings Over Time",
    )
    figure.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#edf3ff",
        xaxis_title="Date",
        yaxis_title="Findings",
    )
    st.plotly_chart(figure, use_container_width=True)


def main() -> None:
    """Render the Domain Lookup page."""
    inject_styles()
    st.title("Domain & Email Lookup")
    st.caption("Search leaked findings to assess exposed domains, emails, and breach indicators")

    with st.container():
        st.markdown("<div class='lookup-shell'>", unsafe_allow_html=True)
        query = st.text_input("Search for a domain or email", placeholder="example.com or analyst@example.com")
        search_clicked = st.button("Search Threat Feed", type="primary")
        st.markdown("</div>", unsafe_allow_html=True)

    if not search_clicked:
        st.info("Enter a domain or email and press Search Threat Feed.")
        return

    query = query.strip()
    if not query:
        st.warning("Please enter a domain or email to search.")
        return

    try:
        with st.spinner("Scanning threat intelligence records..."):
            time.sleep(2)
            results = search_findings(query)

        summary = summarize_findings(results)
        render_status_banner(summary["has_critical"])
        render_summary(summary)
        st.subheader("Findings Timeline")
        render_timeline(results)
        st.subheader("Matched Findings")
        render_results_table(results)
    except Exception as exc:
        LOGGER.exception("Domain lookup page failed: %s", exc)
        st.error(f"Domain lookup failed: {exc}")


if __name__ == "__main__":
    main()
