"""Schemas for DarkShield incident cases."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from api.schemas.alerts import AlertResponse
from api.schemas.findings import FindingResponse, Severity
from api.schemas.investigations import TimelineClusterResponse, TimelineEventResponse


CaseStatus = Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]


class CaseNoteResponse(BaseModel):
    id: str
    case_id: str
    author: str
    body: str
    created_at: datetime


class CaseResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    severity: Severity
    status: CaseStatus
    assigned_analyst: str | None = None
    created_at: datetime
    updated_at: datetime
    tags: list[str] = Field(default_factory=list)
    finding_count: int = Field(default=0, ge=0)
    alert_count: int = Field(default=0, ge=0)
    note_count: int = Field(default=0, ge=0)
    cluster_count: int = Field(default=0, ge=0)


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    severity: Severity = "HIGH"
    status: CaseStatus = "OPEN"
    assigned_analyst: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)


class CaseUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    severity: Severity | None = None
    status: CaseStatus | None = None
    assigned_analyst: str | None = Field(default=None, max_length=120)
    tags: list[str] | None = None


class CaseAttachRequest(BaseModel):
    ids: list[str] = Field(default_factory=list, min_length=1)


class CaseNoteCreateRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class CaseActivityResponse(BaseModel):
    id: str
    activity_type: Literal[
        "case_created",
        "case_updated",
        "case_note",
        "finding_linked",
        "alert_linked",
        "finding_event",
        "alert_event",
    ]
    title: str
    summary: str | None = None
    severity: Severity | None = None
    source_type: str | None = None
    timestamp: datetime
    finding: FindingResponse | None = None
    alert: AlertResponse | None = None
    timeline_event: TimelineEventResponse | None = None
    cluster: TimelineClusterResponse | None = None


class CaseDetailResponse(CaseResponse):
    linked_findings: list[FindingResponse] = Field(default_factory=list)
    linked_alerts: list[AlertResponse] = Field(default_factory=list)
    related_clusters: list[TimelineClusterResponse] = Field(default_factory=list)
    notes: list[CaseNoteResponse] = Field(default_factory=list)
    activity_timeline: list[CaseActivityResponse] = Field(default_factory=list)
