"""JWT authentication helpers for DarkShield."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from api.schemas.auth import AuthSession, AuthUser
from core.config import get_settings


LOGGER = logging.getLogger(__name__)


class AuthService:
    """Password verification and JWT session handling."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def authenticate(self, username: str, password: str) -> AuthUser:
        expected_username = self.settings.auth_username.strip()
        if username.strip() != expected_username:
            raise ValueError("Invalid username or password.")

        if not bcrypt.checkpw(password.encode("utf-8"), self.settings.auth_password_hash.encode("utf-8")):
            raise ValueError("Invalid username or password.")

        return AuthUser(
            username=expected_username,
            display_name=self.settings.auth_display_name.strip(),
            role=self.settings.auth_role.strip(),
        )

    def create_session(self, user: AuthUser) -> AuthSession:
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=self.settings.auth_access_token_minutes,
        )
        payload = {
            "sub": user.username,
            "name": user.display_name,
            "role": user.role,
            "iat": datetime.now(timezone.utc),
            "exp": expires_at,
        }
        access_token = jwt.encode(
            payload,
            self.settings.auth_jwt_secret,
            algorithm="HS256",
        )

        return AuthSession(access_token=access_token, expires_at=expires_at, user=user)

    def decode_session(self, token: str) -> AuthSession:
        payload = jwt.decode(
            token,
            self.settings.auth_jwt_secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp"]},
        )

        if payload.get("sub") != self.settings.auth_username.strip():
            raise ValueError("Invalid token subject.")

        user = AuthUser(
            username=str(payload.get("sub", "")),
            display_name=str(payload.get("name") or self.settings.auth_display_name).strip(),
            role=str(payload.get("role") or self.settings.auth_role).strip(),
        )
        expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)

        return AuthSession(access_token=token, expires_at=expires_at, user=user)


auth_service = AuthService()
