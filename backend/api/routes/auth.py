"""Authentication routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies.auth import require_current_session, require_current_user
from api.schemas.auth import AuthMeResponse, AuthSession, AuthUser, LoginRequest
from api.services.auth_service import auth_service


LOGGER = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=AuthSession)
async def login(payload: LoginRequest) -> AuthSession:
    try:
        user = auth_service.authenticate(payload.username, payload.password)
        return auth_service.create_session(user)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.get("/me", response_model=AuthMeResponse)
async def me(current_session: AuthSession = Depends(require_current_session)) -> AuthMeResponse:
    return AuthMeResponse(expires_at=current_session.expires_at, user=current_session.user)
