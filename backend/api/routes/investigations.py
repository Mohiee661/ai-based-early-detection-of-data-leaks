"""Routes for DarkShield investigation timelines."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from api.dependencies.auth import require_current_user
from api.schemas.findings import Severity
from api.schemas.investigations import ThreatTimelineResponse, TimelineGroupBy, TimelineRange
from api.services.investigations_service import investigations_service


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["investigations"], dependencies=[Depends(require_current_user)])


@router.get("/investigations/timeline", response_model=ThreatTimelineResponse)
async def get_timeline(
    range: TimelineRange = Query(default="30d", pattern="^(7d|30d|90d|all)$"),
    severity: Severity | None = Query(default=None),
    group_by: TimelineGroupBy = Query(default="cluster", pattern="^(cluster|time)$"),
) -> ThreatTimelineResponse:
    try:
        return await investigations_service.fetch_timeline(range, severity, group_by)
    except RuntimeError as exc:
        LOGGER.exception("Timeline query unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected timeline query failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load investigation timeline.") from exc
