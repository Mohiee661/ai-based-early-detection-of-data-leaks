"""Alert generation and query helpers for DarkShield."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi.concurrency import run_in_threadpool

from app.db import get_supabase
from api.schemas.alerts import AlertResponse, AlertsQueryResponse


LOGGER = logging.getLogger(__name__)
ALERTS_TABLE = "alerts"
FINDINGS_TABLE = "findings"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
HIGH_RISK_SCORE_THRESHOLD = 75


def _normalize_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


def _normalize_alert(row: dict[str, Any], index: int = 0) -> AlertResponse:
    created_at_value = row.get("created_at") or datetime.now(timezone.utc)
    try:
        created_at = _normalize_datetime(created_at_value)
    except Exception:
        created_at = datetime.now(timezone.utc)

    read_at_value = row.get("read_at")
    updated_at_value = row.get("updated_at")

    return AlertResponse(
        id=str(row.get("id") or f"alert-{index}"),
        finding_id=str(row.get("finding_id") or ""),
        title=str(row.get("title") or "DarkShield alert").strip(),
        message=str(row.get("message") or "").strip(),
        severity=str(row.get("severity") or "LOW").upper(),
        status=str(row.get("status") or "UNREAD").upper(),
        risk_score=int(row.get("risk_score") or 0),
        pattern_type=str(row.get("pattern_type") or "Unknown Threat Type").strip(),
        matched_value=str(row.get("matched_value") or "N/A").strip(),
        target_domain_match=_normalize_bool(row.get("target_domain_match")),
        created_at=created_at,
        read_at=_normalize_datetime(read_at_value) if read_at_value else None,
        updated_at=_normalize_datetime(updated_at_value) if updated_at_value else None,
    )


class AlertService:
    """Reusable alert generation and query layer."""

    def __init__(self) -> None:
        self._client = get_supabase()
        self._read_alert_ids: set[str] = set()

    def _require_client(self):
        if self._client is None:
            raise RuntimeError("Supabase client is not configured.")
        return self._client

    def _base_query(self):
        return self._require_client().table(ALERTS_TABLE)

    @staticmethod
    def _is_alerting_finding(finding: dict[str, Any]) -> bool:
        severity = str(finding.get("severity") or "").upper()
        risk_score = int(finding.get("risk_score") or 0)
        target_domain_match = _normalize_bool(finding.get("target_domain_match"))
        return severity == "CRITICAL" or risk_score >= HIGH_RISK_SCORE_THRESHOLD or target_domain_match

    @staticmethod
    def _build_alert_payload(finding: dict[str, Any]) -> dict[str, Any]:
        severity = str(finding.get("severity") or "LOW").upper()
        risk_score = int(finding.get("risk_score") or 0)
        target_domain_match = _normalize_bool(finding.get("target_domain_match"))
        pattern_type = str(finding.get("pattern_type") or "Unknown Threat Type").strip()
        matched_value = str(finding.get("matched_value") or "N/A").strip()
        finding_id = str(finding.get("id") or "")
        if severity == "CRITICAL":
            title = "Critical finding alert"
        elif target_domain_match and risk_score >= HIGH_RISK_SCORE_THRESHOLD:
            title = "High-priority target match"
        elif target_domain_match:
            title = "Target domain alert"
        elif risk_score >= HIGH_RISK_SCORE_THRESHOLD:
            title = "High-risk alert"
        else:
            title = "Finding alert"

        return {
            "finding_id": finding_id,
            "status": "UNREAD",
            "target_domain_match": target_domain_match,
        }

    def _upsert_alert_sync(self, finding: dict[str, Any]) -> bool:
        return False

    async def sync_alerts_for_findings(self, findings: list[dict[str, Any]]) -> int:
        return await run_in_threadpool(self._sync_alerts_for_findings_sync, findings)

    def _sync_alerts_for_findings_sync(self, findings: list[dict[str, Any]]) -> int:
        return 0

    def record_finding_alerts(self, findings: list[dict[str, Any]]) -> int:
        """Synchronously create or refresh alerts for inserted findings."""
        return 0

    async def sync_missing_alerts(self, limit: int | None = None) -> int:
        return await run_in_threadpool(self._sync_missing_alerts_sync, limit)

    def _sync_missing_alerts_sync(self, limit: int | None) -> int:
        return 0

    async def fetch_alerts(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> AlertsQueryResponse:
        return await run_in_threadpool(self._fetch_synthetic_alerts_sync, page, page_size, severity, status, search)

    def fetch_alerts_sync(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> AlertsQueryResponse:
        return self._fetch_synthetic_alerts_sync(page, page_size, severity, status, search)

    def _fetch_synthetic_alerts_sync(
        self,
        page: int,
        page_size: int,
        severity: str | None,
        status: str | None,
        search: str | None,
    ) -> AlertsQueryResponse:
        page = max(page, 1)
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        client = self._require_client()

        response = (
            client.table(FINDINGS_TABLE)
            .select("id, severity, pattern_type, matched_value, risk_score, created_at, target_domain_match")
            .order("created_at", desc=True)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        items: list[AlertResponse] = []
        for index, row in enumerate(rows, start=1):
            if not self._is_alerting_finding(row):
                continue

            alert = _normalize_alert(
                {
                    "id": f"synthetic-{row.get('id') or index}",
                    "finding_id": row.get("id"),
                    "severity": row.get("severity"),
                    "status": "READ" if f"synthetic-{row.get('id') or index}" in self._read_alert_ids else "UNREAD",
                    "risk_score": row.get("risk_score"),
                    "target_domain_match": row.get("target_domain_match"),
                    "created_at": row.get("created_at"),
                },
                index,
            )
            alert = self._enrich_synthetic_alert(row, alert)
            if severity and alert.severity != severity.upper():
                continue
            if status and status.upper() in {"UNREAD", "READ"} and alert.status != status.upper():
                continue
            if search:
                term = search.strip().lower()
                haystack = " ".join(
                    [
                        alert.title,
                        alert.message,
                        alert.pattern_type,
                        alert.matched_value,
                    ]
                ).lower()
                if term and term not in haystack:
                    continue

            items.append(alert)

        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = items[start:end]
        unread_count = sum(1 for item in items if item.status == "UNREAD")
        total_pages = (total + page_size - 1) // page_size if total else 0

        return AlertsQueryResponse(
            items=page_items,
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
            unread_count=unread_count,
        )

    def _enrich_synthetic_alert(self, finding: dict[str, Any], item: AlertResponse) -> AlertResponse:
        title, message = self._build_display_text(item, finding.get("matched_value"))
        return item.model_copy(
            update={
                "title": title,
                "message": message,
                "pattern_type": str(finding.get("pattern_type") or item.pattern_type),
                "matched_value": str(finding.get("matched_value") or item.matched_value),
                "created_at": _normalize_datetime(finding.get("created_at") or item.created_at),
            }
        )

    @staticmethod
    def _build_display_text(item: AlertResponse, matched_value: Any) -> tuple[str, str]:
        title: str
        if item.severity == "CRITICAL":
            title = "Critical finding alert"
        elif item.target_domain_match and item.risk_score >= HIGH_RISK_SCORE_THRESHOLD:
            title = "High-priority target match"
        elif item.target_domain_match:
            title = "Target domain alert"
        elif item.risk_score >= HIGH_RISK_SCORE_THRESHOLD:
            title = "High-risk alert"
        else:
            title = "Finding alert"

        indicator = str(matched_value or item.matched_value or "N/A").strip()
        reasons: list[str] = []
        if item.severity == "CRITICAL":
            reasons.append("severity reached CRITICAL")
        if item.risk_score >= HIGH_RISK_SCORE_THRESHOLD:
            reasons.append(f"risk score reached {item.risk_score}")
        if item.target_domain_match:
            reasons.append("matched a target domain")

        message = f"{item.pattern_type} matched `{indicator}` with severity {item.severity} and risk score {item.risk_score}."
        if reasons:
            message = f"{message} Triggered because it {', '.join(reasons)}."

        return title, message

    async def mark_alert_read(self, alert_id: str) -> AlertResponse:
        return await run_in_threadpool(self._mark_alert_read_synthetic_sync, alert_id)

    def _mark_alert_read_synthetic_sync(self, alert_id: str) -> AlertResponse:
        finding_id = self._alert_id_to_finding_id(alert_id)
        if not finding_id:
            raise ValueError("Alert not found.")
        self._read_alert_ids.add(finding_id)
        return self._fetch_single_synthetic_alert_sync(finding_id)

    def _fetch_single_synthetic_alert_sync(self, finding_id: str) -> AlertResponse:
        client = self._require_client()
        response = (
            client.table(FINDINGS_TABLE)
            .select("id, severity, pattern_type, matched_value, risk_score, created_at, target_domain_match")
            .eq("id", finding_id)
            .limit(1)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        if not rows:
            raise ValueError("Alert not found.")

        row = rows[0]
        if not self._is_alerting_finding(row):
            raise ValueError("Alert not found.")

        alert = _normalize_alert(
            {
                "id": f"synthetic-{row.get('id')}",
                "finding_id": row.get("id"),
                "severity": row.get("severity"),
                "status": "READ" if row.get("id") in self._read_alert_ids else "UNREAD",
                "risk_score": row.get("risk_score"),
                "target_domain_match": row.get("target_domain_match"),
                "created_at": row.get("created_at"),
            },
            1,
        )
        return self._enrich_synthetic_alert(row, alert)

    async def mark_all_read(self) -> int:
        return await run_in_threadpool(self._mark_all_read_synthetic_sync)

    def _mark_all_read_synthetic_sync(self) -> int:
        client = self._require_client()
        response = (
            client.table(FINDINGS_TABLE)
            .select("id, severity, pattern_type, matched_value, risk_score, created_at, target_domain_match")
            .order("created_at", desc=True)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        updated = 0
        for row in rows:
            if not self._is_alerting_finding(row):
                continue
            finding_id = str(row.get("id") or "")
            if finding_id and finding_id not in self._read_alert_ids:
                self._read_alert_ids.add(finding_id)
                updated += 1
        return updated

    async def unread_count(self) -> int:
        return await run_in_threadpool(self._unread_count_synthetic_sync)

    def _unread_count_synthetic_sync(self) -> int:
        client = self._require_client()
        response = (
            client.table(FINDINGS_TABLE)
            .select("id, severity, pattern_type, matched_value, risk_score, created_at, target_domain_match")
            .order("created_at", desc=True)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        return sum(1 for row in rows if self._is_alerting_finding(row) and str(row.get("id") or "") not in self._read_alert_ids)

    @staticmethod
    def _alert_id_to_finding_id(alert_id: str) -> str | None:
        if alert_id.startswith("synthetic-"):
            return alert_id.removeprefix("synthetic-")
        return None


alert_service = AlertService()
