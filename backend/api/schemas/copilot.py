"""Schemas for the DarkShield analyst copilot."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from api.schemas.findings import DashboardMetricsResponse, FindingResponse


class CopilotMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=2000)


class CopilotRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    messages: list[CopilotMessage] = Field(default_factory=list)


class CopilotResponse(BaseModel):
    question: str
    analysis_type: str
    answer: str
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str]
    supporting_findings: list[FindingResponse] = Field(default_factory=list)
    metrics: DashboardMetricsResponse | None = None
    conversation: list[CopilotMessage] = Field(default_factory=list)
