"""Route for indicator lookup."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from api.dependencies.auth import require_current_user
from api.schemas.findings import LookupResponse
from api.services.findings_service import FindingsService


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["lookup"], dependencies=[Depends(require_current_user)])
service = FindingsService()


@router.get("/lookup", response_model=LookupResponse)
async def lookup_findings(q: str = Query(..., min_length=1)) -> LookupResponse:
    try:
        return await service.lookup(q)
    except RuntimeError as exc:
        LOGGER.exception("Lookup unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected lookup failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to run lookup.") from exc
