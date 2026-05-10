"""Supabase database helpers for the DarkShield project."""

from __future__ import annotations

import logging
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional

from core.config import get_settings
from supabase import Client, create_client


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
SCAN_TARGETS_TABLE = "scan_targets"


def _mask_value(value: Optional[str], keep: int = 6) -> str:
    """Return a terminal-safe masked representation of a value."""
    if not value:
        return "<missing>"
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep)}"


def debug_environment() -> None:
    """Print environment diagnostics for Supabase initialization."""
    settings = get_settings()

    print("====================================")
    print("DARKSHIELD SUPABASE DEBUG")
    print("====================================")
    print(f"Current working directory: {Path.cwd()}")
    print(f"Masked Supabase URL: {_mask_value(settings.supabase_url)}")
    print(f"Supabase key exists: {bool(settings.supabase_key)}")
    print(f"Python version: {sys.version}")


@lru_cache(maxsize=1)
def get_supabase() -> Optional[Client]:
    """Create and cache the Supabase client with detailed diagnostics."""
    settings = get_settings()

    try:
        LOGGER.info("Attempting to initialize Supabase client.")
        client: Client = create_client(settings.supabase_url, settings.supabase_key)
        LOGGER.info("[SUCCESS] Supabase client initialized successfully")
        return client
    except Exception as exc:
        LOGGER.exception("Supabase client initialization failed: %s", exc)
        return None


def test_connection() -> bool:
    """Check whether the Supabase connection is working."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase connection test failed because the client was not initialized.")
        return False

    try:
        LOGGER.info("Testing Supabase query against `%s`.", SCAN_TARGETS_TABLE)
        client.table(SCAN_TARGETS_TABLE).select("*").limit(1).execute()
        LOGGER.info("[SUCCESS] Supabase connection test passed")
        return True
    except Exception as exc:
        LOGGER.exception(
            "Supabase connection test failed while querying `%s`: %s",
            SCAN_TARGETS_TABLE,
            exc,
        )
        print(f"[ERROR] Query failed for `{SCAN_TARGETS_TABLE}`: {exc}")
        return False


if __name__ == "__main__":
    debug_environment()
    print(test_connection())
