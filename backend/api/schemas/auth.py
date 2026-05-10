"""Authentication schemas for DarkShield."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AuthUser(BaseModel):
    username: str
    display_name: str
    role: str


class AuthSession(BaseModel):
    access_token: str
    expires_at: datetime
    token_type: str = "bearer"
    user: AuthUser


class AuthMeResponse(BaseModel):
    expires_at: datetime
    user: AuthUser
