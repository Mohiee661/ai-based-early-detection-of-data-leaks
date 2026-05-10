"""Authentication dependencies."""

from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.schemas.auth import AuthSession, AuthUser
from api.services.auth_service import auth_service


LOGGER = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)


def require_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthSession:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    token = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    try:
        return auth_service.decode_session(token)
    except Exception as exc:
        LOGGER.exception("Authentication validation failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session.") from exc


def require_current_user(
    current_session: AuthSession = Depends(require_current_session),
) -> AuthUser:
    return current_session.user
