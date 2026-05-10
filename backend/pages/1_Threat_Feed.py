"""Live SOC-style threat feed for DarkShield."""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
import streamlit as st

from app.db import get_supabase


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
FINDINGS_TABLE = "findings"
PAGE_SIZE = 15
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": "#ff4d6d",
    "HIGH": "#ff9e00",
    "MEDIUM": "#ffd166",
    "LOW": "#9aa5b1",
}


def inject_styles() -> None:
    """Apply cyber-themed styling for the feed page."""
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #07111f 0%, #03070d 100%);
            color: #edf4ff;
        }
        .feed-card {
            background: rgba(9, 20, 36, 0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 1rem 1.1rem;
            margin-bottom: 0.8rem;
        }
        .severity-pill {
            display: inline-block;
            padding: 0.2rem 0.7rem;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.78rem;
            letter-spacing: 0.04em;
        }
        .finding-row {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 14px;
            padding: 0.85rem 1rem;
            margin-bottom: 0.7rem;
            background: rgba(6, 14, 26, 0.75);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Render a colored severity badge."""
    normalized = str(severity or "LOW").upper()
    color = SEVERITY_COLORS.get(normalized, "#9aa5b1")
    return (
        f"<span class='severity-pill' style='background:{color}20; color:{color}; "
        f"border:1px solid {color}50'>{normalized}</span>"
    )


def fetch_findings() -> pd.DataFrame:
    """Fetch findings data from Supabase."""
    client = get_supabase()
    columns = [
        "id",
        "raw_page_id",
        "severity",
        "pattern_type",
        "matched_value",
        "risk_score",
        "created_at",
        "is_reviewed",
        "context_window",
    ]

    if client is None:
        LOGGER.error("Supabase client unavailable while fetching findings.")
        return pd.DataFrame(columns=columns)

    try:
        response = (
            client.table(FINDINGS_TABLE)
            .select(",".join(columns))
            .order("created_at", desc=True)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        dataframe = pd.DataFrame(rows, columns=columns)
        LOGGER.info("Fetched %s finding row(s) for threat feed.", len(dataframe))
        return dataframe
    except Exception as exc:
        LOGGER.exception("Failed to fetch findings: %s", exc)
        st.error(f"Failed to fetch findings: {exc}")
        return pd.DataFrame(columns=columns)


def apply_filters(
    dataframe: pd.DataFrame,
    severity_filter: list[str],
    pattern_filter: list[str],
    minimum_risk_score: int,
    review_filter: str,
    search_term: str,
) -> pd.DataFrame:
    """Apply sidebar and search filters to findings."""
    filtered = dataframe.copy()

    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]
    if pattern_filter:
        filtered = filtered[filtered["pattern_type"].isin(pattern_filter)]

    filtered["risk_score"] = pd.to_numeric(filtered["risk_score"], errors="coerce").fillna(0)
    filtered = filtered[filtered["risk_score"] >= minimum_risk_score]

    if review_filter == "Reviewed only":
        filtered = filtered[filtered["is_reviewed"] == True]  # noqa: E712
    elif review_filter == "Unreviewed only":
        filtered = filtered[filtered["is_reviewed"] != True]  # noqa: E712

    if search_term:
        search_lower = search_term.lower()
        mask = (
            filtered["matched_value"].fillna("").str.lower().str.contains(search_lower)
            | filtered["pattern_type"].fillna("").str.lower().str.contains(search_lower)
            | filtered["context_window"].fillna("").str.lower().str.contains(search_lower)
        )
        filtered = filtered[mask]

    return filtered


def render_filters(dataframe: pd.DataFrame) -> tuple[list[str], list[str], int, str, str]:
    """Render sidebar filters and return selected values."""
    st.sidebar.header("Feed Filters")
    severities = [value for value in SEVERITY_ORDER if value in dataframe["severity"].dropna().unique()]
    pattern_types = sorted(dataframe["pattern_type"].dropna().unique().tolist())
    max_risk = int(pd.to_numeric(dataframe["risk_score"], errors="coerce").fillna(0).max() or 100)

    severity_filter = st.sidebar.multiselect("Severity", options=severities, default=severities)
    pattern_filter = st.sidebar.multiselect("Pattern Type", options=pattern_types, default=pattern_types)
    minimum_risk_score = st.sidebar.slider("Minimum Risk Score", min_value=0, max_value=max(max_risk, 1), value=0)
    review_filter = st.sidebar.radio(
        "Review Status",
        options=["All", "Reviewed only", "Unreviewed only"],
        index=0,
    )
    search_term = st.sidebar.text_input("Search Findings", placeholder="Search values or context...")
    return severity_filter, pattern_filter, minimum_risk_score, review_filter, search_term


def render_finding_selector(dataframe: pd.DataFrame) -> int | None:
    """Render a selector for choosing one visible row."""
    if dataframe.empty:
        return None

    selector_labels = [
        f"{row['severity']} | {row['pattern_type']} | score={int(row['risk_score'])} | {row['matched_value']}"
        for _, row in dataframe.iterrows()
    ]
    selected_label = st.selectbox("Select a finding to inspect", options=selector_labels)
    return selector_labels.index(selected_label)


def render_findings_table(dataframe: pd.DataFrame) -> None:
    """Render the visible findings table."""
    if dataframe.empty:
        st.warning("No findings match the current filters.")
        return

    render_rows = dataframe[["severity", "pattern_type", "matched_value", "risk_score", "created_at", "is_reviewed"]].copy()
    render_rows["severity"] = render_rows["severity"].apply(severity_badge)
    st.markdown(render_rows.to_html(escape=False, index=False), unsafe_allow_html=True)


def render_selected_finding(selected_row: pd.Series | None) -> None:
    """Render expanded details for the chosen finding."""
    if selected_row is None:
        return

    st.subheader("Finding Details")
    st.markdown("<div class='feed-card'>", unsafe_allow_html=True)
    st.markdown(severity_badge(str(selected_row.get("severity", "LOW"))), unsafe_allow_html=True)
    st.write(f"Pattern Type: `{selected_row.get('pattern_type', '')}`")
    st.write(f"Risk Score: `{int(selected_row.get('risk_score', 0) or 0)}`")
    st.write(f"Raw Page ID: `{selected_row.get('raw_page_id', '')}`")
    st.write("Context Window:")
    st.code(str(selected_row.get("context_window", "")), language="text")
    st.markdown("</div>", unsafe_allow_html=True)


def main() -> None:
    """Render the DarkShield live threat feed page."""
    inject_styles()
    st.title("Live Threat Feed")
    st.caption("Real-time SOC-style stream of extracted cybersecurity findings")

    if st.button("Refresh Feed"):
        st.rerun()

    findings_df = fetch_findings()
    if findings_df.empty:
        st.warning("No findings available yet.")
        return

    severity_filter, pattern_filter, minimum_risk_score, review_filter, search_term = render_filters(findings_df)
    filtered_df = apply_filters(
        findings_df,
        severity_filter=severity_filter,
        pattern_filter=pattern_filter,
        minimum_risk_score=minimum_risk_score,
        review_filter=review_filter,
        search_term=search_term,
    )

    sort_column = st.selectbox("Sort By", options=["created_at", "risk_score", "severity"], index=0)
    sort_descending = st.toggle("Sort Descending", value=True)
    filtered_df = filtered_df.sort_values(by=sort_column, ascending=not sort_descending, na_position="last")

    total_pages = max(1, (len(filtered_df) + PAGE_SIZE - 1) // PAGE_SIZE)
    page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    start_index = (int(page_number) - 1) * PAGE_SIZE
    end_index = start_index + PAGE_SIZE
    page_df = filtered_df.iloc[start_index:end_index].reset_index(drop=True)

    st.write(f"Showing {len(page_df)} of {len(filtered_df)} matching findings")
    render_findings_table(page_df)

    selected_index = render_finding_selector(page_df)
    selected_row = page_df.iloc[selected_index] if selected_index is not None and not page_df.empty else None
    render_selected_finding(selected_row)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        LOGGER.exception("Threat feed page failed to render: %s", exc)
        st.error(f"Threat feed page failed to render: {exc}")
