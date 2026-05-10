"""Route for analytics summary."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies.auth import require_current_user
from api.schemas.findings import AnalyticsSummaryResponse
from api.services.findings_service import FindingsService


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analytics"], dependencies=[Depends(require_current_user)])
service = FindingsService()


@router.get("/analytics/summary", response_model=AnalyticsSummaryResponse)
async def analytics_summary() -> AnalyticsSummaryResponse:
    try:
        return await service.analytics_summary()
    except RuntimeError as exc:
        LOGGER.exception("Analytics unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected analytics failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load analytics summary.") from exc
