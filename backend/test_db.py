"""Terminal-friendly Supabase connectivity smoke test for DarkShield."""

from __future__ import annotations

import json
import logging
from typing import Any, Iterable

from app.db import get_supabase, test_connection


LOGGER = logging.getLogger(__name__)
TABLE_NAME = "scan_targets"
ROW_LIMIT = 5
BANNER = (
    "====================================\n"
    "DARKSHIELD DATABASE CONNECTION TEST\n"
    "===================================="
)


def _configure_logging() -> None:
    """Configure basic logging for the database smoke test."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def _print_rows(rows: Iterable[Any]) -> None:
    rows_list = list(rows)
    if not rows_list:
        print(f"[INFO] No rows returned from `{TABLE_NAME}`.")
        return

    print()
    print(f"Retrieved {len(rows_list)} row(s) from `{TABLE_NAME}`:")
    print("-" * 60)
    for index, row in enumerate(rows_list, start=1):
        print(f"[Row {index}]")
        print(json.dumps(row, indent=2, default=str))
        print("-" * 60)


def main() -> None:
    _configure_logging()
    print(BANNER)
    print("Testing Supabase connection...")

    try:
        if not test_connection():
            print("[FAIL] Could not connect to Supabase")
            return

        print("[PASS] Successfully connected to Supabase")

        client = get_supabase()
        if client is None:
            print("[FAIL] Could not connect to Supabase")
            return

        response = client.table(TABLE_NAME).select("*").limit(ROW_LIMIT).execute()
        rows = getattr(response, "data", []) or []
        _print_rows(rows)
    except Exception as exc:
        LOGGER.exception("Unexpected error while testing Supabase connectivity: %s", exc)
        print(f"[FAIL] An unexpected error occurred: {exc}")


if __name__ == "__main__":
    main()
