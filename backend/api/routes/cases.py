"""Routes for DarkShield incident cases."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies.auth import require_current_user
from api.schemas.auth import AuthUser
from api.schemas.cases import (
    CaseAttachRequest,
    CaseCreateRequest,
    CaseDetailResponse,
    CaseListResponse,
    CaseNoteCreateRequest,
    CaseNoteResponse,
    CaseStatus,
    CaseUpdateRequest,
)
from api.schemas.findings import Severity
from api.services.cases_service import cases_service


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["cases"], dependencies=[Depends(require_current_user)])


@router.get("/cases", response_model=CaseListResponse)
async def get_cases(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: CaseStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    search: str | None = Query(default=None, min_length=1),
) -> CaseListResponse:
    try:
        return await cases_service.fetch_cases(page, page_size, status_filter, severity, search)
    except RuntimeError as exc:
        LOGGER.exception("Cases query unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected cases query failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load cases.") from exc


@router.post("/cases", response_model=CaseDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_case(payload: CaseCreateRequest, current_user: AuthUser = Depends(require_current_user)) -> CaseDetailResponse:
    try:
        return await cases_service.create_case(payload, assigned_by=current_user.display_name)
    except RuntimeError as exc:
        LOGGER.exception("Case creation unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case creation failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to create case.") from exc


@router.get("/cases/{case_id}", response_model=CaseDetailResponse)
async def get_case(case_id: str) -> CaseDetailResponse:
    try:
        return await cases_service.get_case(case_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Case detail unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case detail failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load case.") from exc


@router.patch("/cases/{case_id}", response_model=CaseDetailResponse)
async def update_case(case_id: str, payload: CaseUpdateRequest) -> CaseDetailResponse:
    try:
        return await cases_service.update_case(case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Case update unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case update failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update case.") from exc


@router.post("/cases/{case_id}/findings", response_model=CaseDetailResponse)
async def attach_case_findings(case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
    try:
        return await cases_service.attach_findings(case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Case finding attachment unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case finding attachment failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to attach findings.") from exc


@router.post("/cases/{case_id}/alerts", response_model=CaseDetailResponse)
async def attach_case_alerts(case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
    try:
        return await cases_service.attach_alerts(case_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Case alert attachment unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case alert attachment failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to attach alerts.") from exc


@router.post("/cases/{case_id}/notes", response_model=CaseNoteResponse)
async def add_case_note(
    case_id: str,
    payload: CaseNoteCreateRequest,
    current_user: AuthUser = Depends(require_current_user),
) -> CaseNoteResponse:
    try:
        return await cases_service.add_note(case_id, payload, current_user.display_name)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        LOGGER.exception("Case note creation unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        LOGGER.exception("Unexpected case note failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to add note.") from exc
