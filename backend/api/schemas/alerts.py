"""Schemas for DarkShield analyst alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from api.schemas.findings import Severity


AlertStatus = Literal["UNREAD", "READ"]


class AlertResponse(BaseModel):
    id: str
    finding_id: str
    title: str
    message: str
    severity: Severity
    status: AlertStatus
    risk_score: int
    pattern_type: str
    matched_value: str
    target_domain_match: bool = False
    created_at: datetime
    read_at: datetime | None = None
    updated_at: datetime | None = None


class AlertsQueryResponse(BaseModel):
    items: list[AlertResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
    unread_count: int = Field(ge=0)

