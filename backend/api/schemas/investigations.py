"""Schemas for DarkShield investigation timeline responses."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from api.schemas.findings import Severity, TimeSeriesPoint


TimelineRange = Literal["7d", "30d", "90d", "all"]
TimelineGroupBy = Literal["cluster", "time"]
TimelineEventType = Literal["finding", "github_exposure", "alert", "incident"]


class TimelineEventResponse(BaseModel):
    id: str
    event_type: TimelineEventType
    title: str
    timestamp: datetime
    severity: Severity
    source_type: str
    pattern_type: str | None = None
    matched_value: str | None = None
    finding_id: str | None = None
    alert_id: str | None = None
    cluster_id: str | None = None
    summary: str | None = None
    related_count: int = Field(default=0, ge=0)
    target_domain_match: bool = False
    unread: bool | None = None


class TimelineClusterResponse(BaseModel):
    cluster_id: str
    label: str
    severity: Severity
    severity_counts: dict[str, int]
    source_types: list[str]
    finding_count: int
    alert_count: int
    incident_count: int
    average_similarity: float = Field(ge=0.0, le=1.0)
    average_risk_score: float = Field(ge=0.0)
    first_seen: datetime
    last_seen: datetime
    shared_keywords: list[str]
    shared_indicators: list[str]
    timeline: list[TimeSeriesPoint]
    finding_ids: list[str]
    alert_ids: list[str]
    incident_event_id: str | None = None


class ThreatTimelineResponse(BaseModel):
    range: TimelineRange
    group_by: TimelineGroupBy
    severity_filter: Severity | None = None
    total_findings: int
    total_alerts: int
    total_events: int
    incident_count: int
    github_exposure_count: int
    events: list[TimelineEventResponse]
    clusters: list[TimelineClusterResponse]
