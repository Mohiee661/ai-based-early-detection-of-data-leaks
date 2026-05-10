"""Routes for findings and dashboard metrics."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from api.dependencies.auth import require_current_user
from api.schemas.findings import DashboardMetricsResponse, FindingsQueryResponse
from api.services.findings_service import FindingsService


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["findings"], dependencies=[Depends(require_current_user)])
service = FindingsService()


@router.get("/findings", response_model=FindingsQueryResponse)
async def get_findings(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None, min_length=1),
) -> FindingsQueryResponse:
    try:
        return await service.fetch_findings(page, page_size, sort_by, sort_order, severity, search)
    except RuntimeError as exc:
        LOGGER.exception("Findings query unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected findings query failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load findings.") from exc


@router.get("/dashboard/metrics", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics() -> DashboardMetricsResponse:
    try:
        return await service.fetch_dashboard_metrics()
    except RuntimeError as exc:
        LOGGER.exception("Metrics query unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected metrics query failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load dashboard metrics.") from exc
