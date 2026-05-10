"""Central application configuration for DarkShield."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from dotenv import load_dotenv

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
ENV_PATHS = [BACKEND_ROOT / ".env", REPO_ROOT / ".env"]


def _load_environment_files() -> None:
    for env_path in ENV_PATHS:
        if env_path.exists():
            load_dotenv(env_path, override=False)


class Settings(BaseSettings):
    """Validated runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
    )

    supabase_url: str = Field(alias="SUPABASE_URL")
    supabase_key: str = Field(alias="SUPABASE_KEY")
    allowed_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000"], alias="ALLOWED_ORIGINS")
    api_prefix: str = Field(default="/api", alias="API_PREFIX")
    auth_username: str = Field(default="analyst", alias="AUTH_USERNAME")
    auth_display_name: str = Field(default="DarkShield Analyst", alias="AUTH_DISPLAY_NAME")
    auth_role: str = Field(default="analyst", alias="AUTH_ROLE")
    auth_password_hash: str = Field(alias="AUTH_PASSWORD_HASH")
    auth_jwt_secret: str = Field(alias="AUTH_JWT_SECRET")
    auth_access_token_minutes: int = Field(default=480, alias="AUTH_ACCESS_TOKEN_MINUTES")
    enable_gpu: bool = Field(default=True, alias="ENABLE_GPU")
    enable_shap: bool = Field(default=False, alias="ENABLE_SHAP")

    @field_validator(
        "supabase_url",
        "supabase_key",
        "api_prefix",
        "auth_username",
        "auth_display_name",
        "auth_role",
        "auth_password_hash",
        "auth_jwt_secret",
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be empty")
        return normalized

    @field_validator("auth_access_token_minutes")
    @classmethod
    def _positive_minutes(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be greater than zero")
        return value

    @field_validator("enable_gpu", "enable_shap", mode="before")
    @classmethod
    def _parse_bool_flags(cls, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
        raise ValueError("must be a boolean flag")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> list[str]:
        if value is None:
            return ["http://localhost:3000"]
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()] or ["http://localhost:3000"]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()] or ["http://localhost:3000"]
        return ["http://localhost:3000"]

    @field_validator("allowed_origins")
    @classmethod
    def _dedupe_origins(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in value:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings."""
    _load_environment_files()
    return Settings()
