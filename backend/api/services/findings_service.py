"""Supabase-backed data access for DarkShield findings and analytics."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import ceil
from typing import Any

from fastapi.concurrency import run_in_threadpool

from app.db import get_supabase
from api.schemas.findings import (
    AnalyticsSummaryResponse,
    DashboardMetricsResponse,
    FindingResponse,
    FindingsQueryResponse,
    LookupResponse,
    PatternTypeBucket,
    SeverityBucket,
    TimeSeriesPoint,
)


LOGGER = logging.getLogger(__name__)
FINDINGS_TABLE = "findings"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 200
MAX_LOOKUP_RESULTS = 100
FINDING_COLUMNS_WITH_AI = (
    "id, severity, pattern_type, matched_value, risk_score, created_at, context_window, "
    "ai_label, ai_confidence, groq_summary, shap_explanation, reasoning_summary, embedding_metadata, classifier_metadata"
)
FINDING_COLUMNS_BASE = "id, severity, pattern_type, matched_value, risk_score, created_at, context_window"


def _normalize_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _normalize_finding(row: dict[str, Any], index: int = 0) -> FindingResponse:
    created_at_value = row.get("created_at") or datetime.now(timezone.utc)
    try:
        created_at = _normalize_datetime(created_at_value)
    except Exception:
        created_at = datetime.now(timezone.utc)

    classifier_metadata = row.get("classifier_metadata")
    source_type = row.get("source_type")
    if source_type is None and isinstance(classifier_metadata, dict):
        source_type = classifier_metadata.get("source_type")

    return FindingResponse(
        id=str(row.get("id") or f"finding-{index}"),
        severity=str(row.get("severity") or "LOW").upper(),
        pattern_type=str(row.get("pattern_type") or "Unknown Threat Type").strip(),
        matched_value=str(row.get("matched_value") or "N/A").strip(),
        risk_score=int(row.get("risk_score") or 0),
        created_at=created_at,
        context_window=row.get("context_window"),
        source_type=str(source_type).strip() if source_type else None,
        ai_label=row.get("ai_label"),
        ai_confidence=float(row["ai_confidence"]) if row.get("ai_confidence") is not None else None,
        groq_summary=row.get("groq_summary"),
        shap_explanation=row.get("shap_explanation"),
        reasoning_summary=row.get("reasoning_summary"),
        embedding_metadata=row.get("embedding_metadata"),
        classifier_metadata=row.get("classifier_metadata"),
    )


class FindingsService:
    """Reusable query layer for backend routes."""

    def __init__(self) -> None:
        self._client = get_supabase()
        self._ai_columns_supported = self._probe_ai_columns()

    def _require_client(self):
        if self._client is None:
            raise RuntimeError("Supabase client is not configured.")
        return self._client

    def _probe_ai_columns(self) -> bool:
        client = self._client
        if client is None:
            return False

        try:
            client.table(FINDINGS_TABLE).select("ai_label").limit(1).execute()
            return True
        except Exception as exc:
            LOGGER.info("AI findings columns unavailable; using base schema fallback: %s", exc)
            return False

    def _base_query(self):
        return self._require_client().table(FINDINGS_TABLE)

    def _select_findings_rows(self, include_ai: bool = True, count_exact: bool = False):
        columns = FINDING_COLUMNS_WITH_AI if include_ai and self._ai_columns_supported else FINDING_COLUMNS_BASE
        query = self._base_query().select(columns, count="exact" if count_exact else None)
        return query

    async def fetch_findings(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        severity: str | None = None,
        search: str | None = None,
    ) -> FindingsQueryResponse:
        return await run_in_threadpool(
            self._fetch_findings_sync,
            page,
            page_size,
            sort_by,
            sort_order,
            severity,
            search,
        )

    def fetch_findings_sync(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        severity: str | None = None,
        search: str | None = None,
    ) -> FindingsQueryResponse:
        return self._fetch_findings_sync(page, page_size, sort_by, sort_order, severity, search)

    def _fetch_findings_sync(
        self,
        page: int,
        page_size: int,
        sort_by: str,
        sort_order: str,
        severity: str | None,
        search: str | None,
    ) -> FindingsQueryResponse:
        page = max(page, 1)
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        offset = (page - 1) * page_size
        client = self._require_client()

        try:
            query = self._select_findings_rows(include_ai=True, count_exact=True)
            if severity:
                query = query.eq("severity", severity.upper())
            if search:
                term = search.strip()
                query = query.or_(f"matched_value.ilike.%{term}%,context_window.ilike.%{term}%")
            if sort_by not in {"created_at", "risk_score", "severity", "pattern_type"}:
                sort_by = "created_at"
            ascending = sort_order.lower() == "asc"
            query = query.order(sort_by, desc=not ascending)
            query = query.range(offset, offset + page_size - 1)
            response = query.execute()
        except Exception as exc:
            LOGGER.warning("AI-aware findings query failed, retrying with base columns: %s", exc)
            query = self._select_findings_rows(include_ai=False, count_exact=True)
            if severity:
                query = query.eq("severity", severity.upper())
            if search:
                term = search.strip()
                query = query.or_(f"matched_value.ilike.%{term}%,context_window.ilike.%{term}%")
            if sort_by not in {"created_at", "risk_score", "severity", "pattern_type"}:
                sort_by = "created_at"
            ascending = sort_order.lower() == "asc"
            query = query.order(sort_by, desc=not ascending)
            query = query.range(offset, offset + page_size - 1)
            response = query.execute()
        rows = getattr(response, "data", []) or []
        total = int(getattr(response, "count", len(rows)) or 0)
        items = [_normalize_finding(row, index) for index, row in enumerate(rows, start=1)]
        total_pages = ceil(total / page_size) if total else 0

        return FindingsQueryResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        )

    async def fetch_dashboard_metrics(self) -> DashboardMetricsResponse:
        return await run_in_threadpool(self._fetch_dashboard_metrics_sync)

    def _fetch_dashboard_metrics_sync(self) -> DashboardMetricsResponse:
        client = self._require_client()
        today_start = datetime.now(timezone.utc).date()

        try:
            response = (
                client.table(FINDINGS_TABLE)
                .select("severity, pattern_type, matched_value, created_at")
                .order("created_at", desc=True)
                .execute()
            )
            rows = getattr(response, "data", []) or []
        except Exception as exc:
            LOGGER.warning("Dashboard metrics query failed, returning safe fallback: %s", exc)
            rows = []

        critical_result = 0
        high_result = 0
        findings_today_result = 0
        api_key_exposures_result = 0

        for row in rows:
            severity = str(row.get("severity") or "").upper()
            pattern_type = str(row.get("pattern_type") or "").lower()
            matched_value = str(row.get("matched_value") or "").lower()
            created_at_value = row.get("created_at")

            if severity == "CRITICAL":
                critical_result += 1
            if severity == "HIGH":
                high_result += 1

            try:
                created_at = _normalize_datetime(created_at_value)
                if created_at.date() >= today_start:
                    findings_today_result += 1
            except Exception:
                pass

            if "api" in pattern_type or "api_key" in matched_value:
                api_key_exposures_result += 1

        return DashboardMetricsResponse(
            total_findings=len(rows),
            critical_findings=critical_result,
            high_findings=high_result,
            findings_today=findings_today_result,
            api_key_exposures=api_key_exposures_result,
        )

    async def lookup(self, query: str) -> LookupResponse:
        return await run_in_threadpool(self._lookup_sync, query)

    def _lookup_sync(self, query: str) -> LookupResponse:
        client = self._require_client()
        term = query.strip()
        if not term:
            return LookupResponse(query=term, count=0, items=[])

        columns = FINDING_COLUMNS_WITH_AI if self._ai_columns_supported else FINDING_COLUMNS_BASE
        response = (
            client.table(FINDINGS_TABLE)
            .select(columns, count="exact")
            .or_(f"matched_value.ilike.%{term}%,context_window.ilike.%{term}%")
            .order("created_at", desc=True)
            .limit(MAX_LOOKUP_RESULTS)
            .execute()
        )

        rows = getattr(response, "data", []) or []
        items = [_normalize_finding(row, index) for index, row in enumerate(rows, start=1)]
        return LookupResponse(query=term, count=int(getattr(response, "count", len(items)) or len(items)), items=items)

    async def analytics_summary(self) -> AnalyticsSummaryResponse:
        return await run_in_threadpool(self._analytics_summary_sync)

    def _analytics_summary_sync(self) -> AnalyticsSummaryResponse:
        client = self._require_client()
        select_columns = "severity, pattern_type, created_at, ai_label, ai_confidence"
        if not self._ai_columns_supported:
            select_columns = "severity, pattern_type, created_at"

        response = (
            client.table(FINDINGS_TABLE)
            .select(select_columns)
            .order("created_at", desc=False)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        findings = [_normalize_finding(row, index) for index, row in enumerate(rows, start=1)]

        severity_counts = Counter(finding.severity for finding in findings)
        severity_distribution = [
            SeverityBucket(severity=severity, count=severity_counts.get(severity, 0))
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        ]

        time_buckets: dict[str, int] = defaultdict(int)
        pattern_counts = Counter()
        for finding in findings:
            date_key = finding.created_at.date().isoformat()
            time_buckets[date_key] += 1
            pattern_counts[finding.pattern_type] += 1

        findings_over_time = [
            TimeSeriesPoint(date=date, count=count)
            for date, count in sorted(time_buckets.items())
        ]
        top_pattern_types = [
            PatternTypeBucket(pattern_type=pattern_type, count=count)
            for pattern_type, count in pattern_counts.most_common(10)
        ]

        return AnalyticsSummaryResponse(
            severity_distribution=severity_distribution,
            findings_over_time=findings_over_time,
            top_pattern_types=top_pattern_types,
        )

    async def health_check(self) -> bool:
        return await run_in_threadpool(self._health_check_sync)

    def _health_check_sync(self) -> bool:
        try:
            self._require_client().table(FINDINGS_TABLE).select("id", count="exact").limit(1).execute()
            return True
        except Exception as exc:
            LOGGER.exception("Health check failed: %s", exc)
            return False
