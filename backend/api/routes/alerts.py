"""Routes for analyst alerts."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies.auth import require_current_user
from api.schemas.alerts import AlertResponse, AlertsQueryResponse
from api.services.alerts_service import alert_service


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["alerts"], dependencies=[Depends(require_current_user)])


@router.get("/alerts", response_model=AlertsQueryResponse)
async def get_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, min_length=1),
) -> AlertsQueryResponse:
    try:
        return await alert_service.fetch_alerts(page, page_size, severity, status_filter, search)
    except RuntimeError as exc:
        LOGGER.exception("Alerts query unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected alerts query failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load alerts.") from exc


@router.patch("/alerts/{alert_id}/read", response_model=AlertResponse)
async def mark_alert_read(alert_id: str) -> AlertResponse:
    try:
        return await alert_service.mark_alert_read(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Mark alert read unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected alert update failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update alert.") from exc


@router.post("/alerts/read-all", response_model=dict[str, int])
async def mark_all_alerts_read() -> dict[str, int]:
    try:
        updated = await alert_service.mark_all_read()
        return {"updated": updated}
    except RuntimeError as exc:
        LOGGER.exception("Mark all alerts read unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected alerts bulk update failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update alerts.") from exc


@router.get("/alerts/unread-count", response_model=dict[str, int])
async def get_unread_alert_count() -> dict[str, int]:
    try:
        return {"unread_count": await alert_service.unread_count()}
    except RuntimeError as exc:
        LOGGER.exception("Unread alerts count unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected unread alerts count failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load unread alert count.") from exc

