"""Pydantic schemas for DarkShield API responses and queries."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class FindingResponse(BaseModel):
    id: str
    severity: Severity
    pattern_type: str
    matched_value: str
    risk_score: int
    created_at: datetime
    context_window: str | None = None
    source_type: str | None = None
    ai_label: str | None = None
    ai_confidence: float | None = None
    groq_summary: str | None = None
    shap_explanation: str | None = None
    reasoning_summary: str | None = None
    embedding_metadata: dict[str, object] | None = None
    classifier_metadata: dict[str, object] | None = None


class FindingsQueryResponse(BaseModel):
    items: list[FindingResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class DashboardMetricsResponse(BaseModel):
    total_findings: int
    critical_findings: int
    high_findings: int
    findings_today: int
    api_key_exposures: int


class SeverityBucket(BaseModel):
    severity: Severity
    count: int


class TimeSeriesPoint(BaseModel):
    date: str
    count: int = Field(ge=0)


class PatternTypeBucket(BaseModel):
    pattern_type: str
    count: int = Field(ge=0)


class AnalyticsSummaryResponse(BaseModel):
    severity_distribution: list[SeverityBucket]
    findings_over_time: list[TimeSeriesPoint]
    top_pattern_types: list[PatternTypeBucket]


class LookupResponse(BaseModel):
    query: str
    count: int
    items: list[FindingResponse]


class HealthResponse(BaseModel):
    status: str
    database_connected: bool
    checked_at: datetime
