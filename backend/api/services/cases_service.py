"""Case management for DarkShield investigations."""

from __future__ import annotations

import copy
import logging
from collections import defaultdict
from datetime import datetime, timezone
from math import ceil
from typing import Any
from uuid import uuid4

from fastapi.concurrency import run_in_threadpool

from app.db import get_supabase
from api.schemas.alerts import AlertResponse
from api.schemas.cases import (
    CaseActivityResponse,
    CaseAttachRequest,
    CaseCreateRequest,
    CaseDetailResponse,
    CaseListResponse,
    CaseNoteCreateRequest,
    CaseNoteResponse,
    CaseResponse,
    CaseStatus,
    CaseUpdateRequest,
)
from api.schemas.findings import FindingResponse, Severity
from api.schemas.investigations import TimelineClusterResponse, TimelineEventResponse
from api.services.alerts_service import alert_service
from api.services.findings_service import FindingsService, _normalize_finding
from api.services.investigations_service import investigations_service


LOGGER = logging.getLogger(__name__)
CASES_TABLE = "cases"
CASE_FINDINGS_TABLE = "case_findings"
CASE_ALERTS_TABLE = "case_alerts"
CASE_NOTES_TABLE = "case_notes"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _normalize_case(row: dict[str, Any], *, finding_count: int = 0, alert_count: int = 0, note_count: int = 0) -> CaseResponse:
    return CaseResponse(
        id=str(row.get("id") or ""),
        title=str(row.get("title") or "Untitled case").strip(),
        description=row.get("description"),
        severity=str(row.get("severity") or "LOW").upper(),
        status=str(row.get("status") or "OPEN").upper(),
        assigned_analyst=row.get("assigned_analyst"),
        created_at=_normalize_datetime(row.get("created_at") or _now()),
        updated_at=_normalize_datetime(row.get("updated_at") or row.get("created_at") or _now()),
        tags=_normalize_tags(row.get("tags")),
        finding_count=finding_count,
        alert_count=alert_count,
        note_count=note_count,
        cluster_count=int(row.get("cluster_count") or 0),
    )


def _normalize_note(row: dict[str, Any]) -> CaseNoteResponse:
    return CaseNoteResponse(
        id=str(row.get("id") or ""),
        case_id=str(row.get("case_id") or ""),
        author=str(row.get("author") or "analyst"),
        body=str(row.get("body") or "").strip(),
        created_at=_normalize_datetime(row.get("created_at") or _now()),
    )


class CasesService:
    """Supabase-backed case management with in-memory fallback."""

    def __init__(self) -> None:
        self._client = get_supabase()
        self._findings = FindingsService()
        self._tables_supported: bool | None = None
        self._memory_cases: dict[str, dict[str, Any]] = {}
        self._memory_case_findings: dict[str, set[str]] = defaultdict(set)
        self._memory_case_alerts: dict[str, set[str]] = defaultdict(set)
        self._memory_case_notes: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def _require_client(self):
        if self._client is None:
            raise RuntimeError("Supabase client is not configured.")
        return self._client

    def _supports_tables(self) -> bool:
        if self._tables_supported is not None:
            return self._tables_supported

        client = self._client
        if client is None:
            self._tables_supported = False
            return False

        try:
            client.table(CASES_TABLE).select("id").limit(1).execute()
            self._tables_supported = True
            return True
        except Exception as exc:
            LOGGER.info("Case tables unavailable; falling back to in-memory store: %s", exc)
            self._tables_supported = False
            return False

    def _case_counts(self, case_id: str) -> tuple[int, int, int]:
        if self._supports_tables():
            try:
                client = self._require_client()
                findings = client.table(CASE_FINDINGS_TABLE).select("finding_id", count="exact").eq("case_id", case_id).execute()
                alerts = client.table(CASE_ALERTS_TABLE).select("alert_id", count="exact").eq("case_id", case_id).execute()
                notes = client.table(CASE_NOTES_TABLE).select("id", count="exact").eq("case_id", case_id).execute()
                return (
                    int(getattr(findings, "count", 0) or 0),
                    int(getattr(alerts, "count", 0) or 0),
                    int(getattr(notes, "count", 0) or 0),
                )
            except Exception as exc:
                LOGGER.warning("Case count lookup failed; using fallback counts: %s", exc)

        return (
            len(self._memory_case_findings.get(case_id, set())),
            len(self._memory_case_alerts.get(case_id, set())),
            len(self._memory_case_notes.get(case_id, [])),
        )

    async def fetch_cases(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        status: CaseStatus | None = None,
        severity: Severity | None = None,
        search: str | None = None,
    ) -> CaseListResponse:
        return await run_in_threadpool(self._fetch_cases_sync, page, page_size, status, severity, search)

    def _fetch_cases_sync(
        self,
        page: int,
        page_size: int,
        status: CaseStatus | None,
        severity: Severity | None,
        search: str | None,
    ) -> CaseListResponse:
        page = max(1, page)
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        term = search.strip().lower() if search else ""

        if self._supports_tables():
            try:
                client = self._require_client()
                query = client.table(CASES_TABLE).select("*", count="exact").order("updated_at", desc=True)
                if status:
                    query = query.eq("status", status.upper())
                if severity:
                    query = query.eq("severity", severity.upper())
                if term:
                    query = query.or_(f"title.ilike.%{term}%,description.ilike.%{term}%,assigned_analyst.ilike.%{term}%")

                query = query.range((page - 1) * page_size, (page * page_size) - 1)
                response = query.execute()
                rows = getattr(response, "data", []) or []
                items = []
                for row in rows:
                    counts = self._case_counts(str(row.get("id") or ""))
                    items.append(
                        _normalize_case(
                            row,
                            finding_count=counts[0],
                            alert_count=counts[1],
                            note_count=counts[2],
                        )
                    )
                total = int(getattr(response, "count", len(items)) or len(items))
                total_pages = ceil(total / page_size) if total else 0
                return CaseListResponse(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)
            except Exception as exc:
                LOGGER.warning("Case table query failed; using in-memory fallback: %s", exc)

        cases = list(self._memory_cases.values())
        if status:
            cases = [case for case in cases if str(case.get("status") or "").upper() == status.upper()]
        if severity:
            cases = [case for case in cases if str(case.get("severity") or "").upper() == severity.upper()]
        if term:
            cases = [
                case
                for case in cases
                if term in str(case.get("title") or "").lower()
                or term in str(case.get("description") or "").lower()
                or term in " ".join(_normalize_tags(case.get("tags"))).lower()
                or term in str(case.get("assigned_analyst") or "").lower()
            ]

        cases = sorted(cases, key=lambda row: _normalize_datetime(row.get("updated_at") or row.get("created_at")), reverse=True)
        total = len(cases)
        start = (page - 1) * page_size
        end = start + page_size
        page_rows = cases[start:end]
        items = []
        for row in page_rows:
            case_id = str(row.get("id") or "")
            counts = self._case_counts(case_id)
            items.append(_normalize_case(row, finding_count=counts[0], alert_count=counts[1], note_count=counts[2]))

        total_pages = ceil(total / page_size) if total else 0
        return CaseListResponse(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)

    async def create_case(
        self,
        payload: CaseCreateRequest,
        assigned_by: str | None = None,
    ) -> CaseDetailResponse:
        return await run_in_threadpool(self._create_case_sync, payload, assigned_by)

    def _create_case_sync(
        self,
        payload: CaseCreateRequest,
        assigned_by: str | None,
    ) -> CaseDetailResponse:
        case_id = str(uuid4())
        now = _now().isoformat()
        record = {
            "id": case_id,
            "title": payload.title.strip(),
            "description": payload.description,
            "severity": payload.severity,
            "status": payload.status,
            "assigned_analyst": payload.assigned_analyst or assigned_by,
            "created_at": now,
            "updated_at": now,
            "tags": _normalize_tags(payload.tags),
        }

        created = self._persist_case(record)
        if payload.finding_ids:
            self._attach_finding_ids(case_id, payload.finding_ids)
        if payload.alert_ids:
            self._attach_alert_ids(case_id, payload.alert_ids)
        self._add_note_record(case_id, "Case created.", assigned_by or "system")
        return self._build_case_detail(created)

    async def get_case(self, case_id: str) -> CaseDetailResponse:
        return await run_in_threadpool(self._get_case_sync, case_id)

    def _get_case_sync(self, case_id: str) -> CaseDetailResponse:
        case = self._load_case(case_id)
        if case is None:
            raise ValueError("Case not found.")
        return self._build_case_detail(case)

    async def update_case(self, case_id: str, payload: CaseUpdateRequest) -> CaseDetailResponse:
        return await run_in_threadpool(self._update_case_sync, case_id, payload)

    def _update_case_sync(self, case_id: str, payload: CaseUpdateRequest) -> CaseDetailResponse:
        existing = self._load_case(case_id)
        if existing is None:
            raise ValueError("Case not found.")

        updated = copy.deepcopy(existing)
        for field in ("title", "description", "severity", "status", "assigned_analyst"):
            value = getattr(payload, field)
            if value is not None:
                updated[field] = value
        if payload.tags is not None:
            updated["tags"] = _normalize_tags(payload.tags)
        updated["updated_at"] = _now().isoformat()
        self._persist_case(updated)
        self._add_note_record(case_id, "Case updated.", updated.get("assigned_analyst") or "system")
        return self._build_case_detail(updated)

    async def attach_findings(self, case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
        return await run_in_threadpool(self._attach_findings_sync, case_id, payload)

    def _attach_findings_sync(self, case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
        case = self._load_case(case_id)
        if case is None:
            raise ValueError("Case not found.")
        self._attach_finding_ids(case_id, payload.ids)
        self._add_note_record(case_id, f"Attached {len(payload.ids)} finding(s).", case.get("assigned_analyst") or "system")
        return self._build_case_detail(case)

    async def attach_alerts(self, case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
        return await run_in_threadpool(self._attach_alerts_sync, case_id, payload)

    def _attach_alerts_sync(self, case_id: str, payload: CaseAttachRequest) -> CaseDetailResponse:
        case = self._load_case(case_id)
        if case is None:
            raise ValueError("Case not found.")
        self._attach_alert_ids(case_id, payload.ids)
        self._add_note_record(case_id, f"Attached {len(payload.ids)} alert(s).", case.get("assigned_analyst") or "system")
        return self._build_case_detail(case)

    async def add_note(self, case_id: str, payload: CaseNoteCreateRequest, author: str) -> CaseNoteResponse:
        return await run_in_threadpool(self._add_note_sync, case_id, payload, author)

    def _add_note_sync(self, case_id: str, payload: CaseNoteCreateRequest, author: str) -> CaseNoteResponse:
        case = self._load_case(case_id)
        if case is None:
            raise ValueError("Case not found.")
        note = self._add_note_record(case_id, payload.body.strip(), author)
        self._touch_case(case_id)
        return note

    def _persist_case(self, record: dict[str, Any]) -> dict[str, Any]:
        if self._supports_tables():
            try:
                client = self._require_client()
                client.table(CASES_TABLE).upsert(record).execute()
                return record
            except Exception as exc:
                LOGGER.warning("Case persistence failed; using in-memory fallback: %s", exc)

        self._memory_cases[record["id"]] = copy.deepcopy(record)
        return record

    def _load_case(self, case_id: str) -> dict[str, Any] | None:
        if self._supports_tables():
            try:
                response = self._require_client().table(CASES_TABLE).select("*").eq("id", case_id).limit(1).execute()
                rows = getattr(response, "data", []) or []
                if rows:
                    return rows[0]
            except Exception as exc:
                LOGGER.warning("Case load failed; using in-memory fallback: %s", exc)

        return self._memory_cases.get(case_id)

    def _touch_case(self, case_id: str) -> None:
        current = self._load_case(case_id)
        if current is None:
            return
        updated = copy.deepcopy(current)
        updated["updated_at"] = _now().isoformat()
        self._persist_case(updated)

    def _attach_finding_ids(self, case_id: str, finding_ids: list[str]) -> None:
        ids = [str(item).strip() for item in finding_ids if str(item).strip()]
        if not ids:
            return

        if self._supports_tables():
            try:
                client = self._require_client()
                existing = client.table(CASE_FINDINGS_TABLE).select("finding_id").eq("case_id", case_id).execute()
                existing_ids = {
                    str(row.get("finding_id") or "")
                    for row in (getattr(existing, "data", []) or [])
                    if str(row.get("finding_id") or "").strip()
                }
                fresh_ids = [finding_id for finding_id in ids if finding_id not in existing_ids]
                if fresh_ids:
                    client.table(CASE_FINDINGS_TABLE).insert(
                        [{"id": str(uuid4()), "case_id": case_id, "finding_id": finding_id} for finding_id in fresh_ids]
                    ).execute()
                self._touch_case(case_id)
                return
            except Exception as exc:
                LOGGER.warning("Attaching findings failed; using in-memory fallback: %s", exc)

        fresh_ids = [finding_id for finding_id in ids if finding_id not in self._memory_case_findings[case_id]]
        if fresh_ids:
            self._memory_case_findings[case_id].update(fresh_ids)
        self._touch_case(case_id)

    def _attach_alert_ids(self, case_id: str, alert_ids: list[str]) -> None:
        ids = [str(item).strip() for item in alert_ids if str(item).strip()]
        if not ids:
            return

        if self._supports_tables():
            try:
                client = self._require_client()
                existing = client.table(CASE_ALERTS_TABLE).select("alert_id").eq("case_id", case_id).execute()
                existing_ids = {
                    str(row.get("alert_id") or "")
                    for row in (getattr(existing, "data", []) or [])
                    if str(row.get("alert_id") or "").strip()
                }
                fresh_ids = [alert_id for alert_id in ids if alert_id not in existing_ids]
                if fresh_ids:
                    client.table(CASE_ALERTS_TABLE).insert(
                        [{"id": str(uuid4()), "case_id": case_id, "alert_id": alert_id} for alert_id in fresh_ids]
                    ).execute()
                self._touch_case(case_id)
                return
            except Exception as exc:
                LOGGER.warning("Attaching alerts failed; using in-memory fallback: %s", exc)

        fresh_ids = [alert_id for alert_id in ids if alert_id not in self._memory_case_alerts[case_id]]
        if fresh_ids:
            self._memory_case_alerts[case_id].update(fresh_ids)
        self._touch_case(case_id)

    def _add_note_record(self, case_id: str, body: str, author: str) -> CaseNoteResponse:
        note = {
            "id": str(uuid4()),
            "case_id": case_id,
            "author": author.strip() or "analyst",
            "body": body,
            "created_at": _now().isoformat(),
        }

        if self._supports_tables():
            try:
                self._require_client().table(CASE_NOTES_TABLE).insert(note).execute()
                self._touch_case(case_id)
                return _normalize_note(note)
            except Exception as exc:
                LOGGER.warning("Adding note failed; using in-memory fallback: %s", exc)

        self._memory_case_notes[case_id].append(copy.deepcopy(note))
        self._touch_case(case_id)
        return _normalize_note(note)

    def _load_linked_findings(self, case_id: str) -> list[FindingResponse]:
        ids = list(self._memory_case_findings.get(case_id, set()))
        if self._supports_tables():
            try:
                response = (
                    self._require_client()
                    .table(CASE_FINDINGS_TABLE)
                    .select("finding_id")
                    .eq("case_id", case_id)
                    .execute()
                )
                rows = getattr(response, "data", []) or []
                ids = [str(row.get("finding_id") or "") for row in rows if str(row.get("finding_id") or "").strip()]
            except Exception as exc:
                LOGGER.warning("Loading case findings failed; using in-memory fallback: %s", exc)

        if not ids:
            return []

        try:
            response = self._require_client().table("findings").select("*").in_("id", ids).execute()
            rows = getattr(response, "data", []) or []
            return [_normalize_finding(row, index) for index, row in enumerate(rows, start=1)]
        except Exception:
            pass

        all_findings = self._findings.fetch_findings_sync(page_size=200, sort_by="created_at", sort_order="desc")
        return [finding for finding in all_findings.items if finding.id in set(ids)]

    def _load_linked_alerts(self, case_id: str) -> list[AlertResponse]:
        ids = list(self._memory_case_alerts.get(case_id, set()))
        if self._supports_tables():
            try:
                response = (
                    self._require_client()
                    .table(CASE_ALERTS_TABLE)
                    .select("alert_id")
                    .eq("case_id", case_id)
                    .execute()
                )
                rows = getattr(response, "data", []) or []
                ids = [str(row.get("alert_id") or "") for row in rows if str(row.get("alert_id") or "").strip()]
            except Exception as exc:
                LOGGER.warning("Loading case alerts failed; using in-memory fallback: %s", exc)

        if not ids:
            return []

        try:
            response = self._require_client().table("alerts").select("*").in_("id", ids).execute()
            rows = getattr(response, "data", []) or []
            return [self._normalize_alert_row(row) for row in rows]
        except Exception:
            pass

        all_alerts = alert_service.fetch_alerts_sync(page_size=100, severity=None, status=None, search=None)
        return [alert for alert in all_alerts.items if alert.id in set(ids)]

    def _normalize_alert_row(self, row: dict[str, Any]) -> AlertResponse:
        return AlertResponse(
            id=str(row.get("id") or ""),
            finding_id=str(row.get("finding_id") or ""),
            title=str(row.get("title") or "DarkShield alert").strip(),
            message=str(row.get("message") or "").strip(),
            severity=str(row.get("severity") or "LOW").upper(),
            status=str(row.get("status") or "UNREAD").upper(),
            risk_score=int(row.get("risk_score") or 0),
            pattern_type=str(row.get("pattern_type") or "Unknown Threat Type").strip(),
            matched_value=str(row.get("matched_value") or "N/A").strip(),
            target_domain_match=bool(row.get("target_domain_match")),
            created_at=_normalize_datetime(row.get("created_at") or _now()),
            read_at=_normalize_datetime(row.get("read_at")) if row.get("read_at") else None,
            updated_at=_normalize_datetime(row.get("updated_at")) if row.get("updated_at") else None,
        )

    def _load_notes(self, case_id: str) -> list[CaseNoteResponse]:
        if self._supports_tables():
            try:
                response = (
                    self._require_client()
                    .table(CASE_NOTES_TABLE)
                    .select("*")
                    .eq("case_id", case_id)
                    .order("created_at", desc=False)
                    .execute()
                )
                rows = getattr(response, "data", []) or []
                return [_normalize_note(row) for row in rows]
            except Exception as exc:
                LOGGER.warning("Loading case notes failed; using in-memory fallback: %s", exc)

        return [_normalize_note(row) for row in self._memory_case_notes.get(case_id, [])]

    def _build_related_clusters(self, linked_findings: list[FindingResponse]) -> list[TimelineClusterResponse]:
        if not linked_findings:
            return []

        cluster_ids = {finding.id for finding in linked_findings}
        try:
            timeline = investigations_service._fetch_timeline_sync("all", None, "cluster")
            clusters = []
            for cluster in timeline.clusters:
                if cluster.finding_ids and cluster_ids.intersection(cluster.finding_ids):
                    clusters.append(cluster)
            return clusters
        except Exception as exc:
            LOGGER.warning("Building related clusters failed: %s", exc)
            return []

    def _build_activity_timeline(
        self,
        case: CaseResponse,
        linked_findings: list[FindingResponse],
        linked_alerts: list[AlertResponse],
        notes: list[CaseNoteResponse],
        related_clusters: list[TimelineClusterResponse],
    ) -> list[CaseActivityResponse]:
        activities: list[CaseActivityResponse] = [
            CaseActivityResponse(
                id=f"case-created-{case.id}",
                activity_type="case_created",
                title="Case created",
                summary=case.description or case.title,
                severity=case.severity,
                source_type="case",
                timestamp=case.created_at,
            )
        ]

        for finding in linked_findings:
            activities.append(
                CaseActivityResponse(
                    id=f"finding-linked-{finding.id}",
                    activity_type="finding_linked",
                    title="Finding attached",
                    summary=f"{finding.pattern_type} matched {finding.matched_value}.",
                    severity=finding.severity,
                    source_type=finding.source_type or "finding",
                    timestamp=finding.created_at,
                    finding=finding,
                )
            )

        for alert in linked_alerts:
            activities.append(
                CaseActivityResponse(
                    id=f"alert-linked-{alert.id}",
                    activity_type="alert_linked",
                    title="Alert attached",
                    summary=alert.message,
                    severity=alert.severity,
                    source_type="alert",
                    timestamp=alert.created_at,
                    alert=alert,
                )
            )

        for note in notes:
            activities.append(
                CaseActivityResponse(
                    id=f"note-{note.id}",
                    activity_type="case_note",
                    title=f"Note by {note.author}",
                    summary=note.body,
                    severity=None,
                    source_type="case",
                    timestamp=note.created_at,
                )
            )

        for cluster in related_clusters:
            activities.append(
                CaseActivityResponse(
                    id=f"cluster-{cluster.cluster_id}",
                    activity_type="case_updated",
                    title=f"Related cluster: {cluster.label}",
                    summary=f"{cluster.finding_count} findings, {cluster.alert_count} alerts.",
                    severity=cluster.severity,
                    source_type=", ".join(cluster.source_types) if cluster.source_types else "cluster",
                    timestamp=cluster.first_seen,
                    cluster=cluster,
                )
            )

        return sorted(activities, key=lambda item: item.timestamp)

    def _build_case_detail(self, case_row: dict[str, Any]) -> CaseDetailResponse:
        case = _normalize_case(case_row)
        linked_findings = self._load_linked_findings(case.id)
        linked_alerts = self._load_linked_alerts(case.id)
        notes = self._load_notes(case.id)
        related_clusters = self._build_related_clusters(linked_findings)
        case_counts = self._case_counts(case.id)
        case = case.model_copy(
            update={
                "finding_count": case_counts[0],
                "alert_count": case_counts[1],
                "note_count": case_counts[2],
                "cluster_count": len(related_clusters),
            }
        )
        activity_timeline = self._build_activity_timeline(case, linked_findings, linked_alerts, notes, related_clusters)
        return CaseDetailResponse(
            **case.model_dump(),
            linked_findings=linked_findings,
            linked_alerts=linked_alerts,
            related_clusters=related_clusters,
            notes=notes,
            activity_timeline=activity_timeline,
        )


cases_service = CasesService()
