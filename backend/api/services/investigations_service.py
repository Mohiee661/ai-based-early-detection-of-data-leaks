"""Timeline aggregation for DarkShield investigations."""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.concurrency import run_in_threadpool

from api.schemas.alerts import AlertResponse
from api.schemas.findings import FindingResponse, Severity, TimeSeriesPoint
from api.schemas.investigations import (
    ThreatTimelineResponse,
    TimelineClusterResponse,
    TimelineEventResponse,
    TimelineEventType,
    TimelineGroupBy,
    TimelineRange,
)
from api.services.alerts_service import alert_service
from api.services.findings_service import FindingsService


LOGGER = logging.getLogger(__name__)
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{4,}")
STOPWORDS = {
    "http",
    "https",
    "www",
    "com",
    "net",
    "org",
    "info",
    "github",
    "token",
    "key",
    "keys",
    "secret",
    "leak",
    "leaks",
    "alert",
    "finding",
    "incident",
    "https",
}
RANGE_TO_DAYS: dict[TimelineRange, int | None] = {
    "7d": 7,
    "30d": 30,
    "90d": 90,
    "all": None,
}
PAGE_SIZE = 200
ALERT_PAGE_SIZE = 100


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _range_start(range_key: TimelineRange) -> datetime | None:
    days = RANGE_TO_DAYS[range_key]
    if days is None:
        return None
    return datetime.now(timezone.utc) - timedelta(days=days)


def _guess_source_type(finding: FindingResponse) -> str:
    source_type = finding.source_type
    if source_type:
        return source_type

    if finding.classifier_metadata and isinstance(finding.classifier_metadata, dict):
        candidate = finding.classifier_metadata.get("source_type")
        if candidate:
            return str(candidate)

    text = " ".join(
        [
            finding.pattern_type,
            finding.matched_value,
            finding.context_window or "",
        ]
    ).lower()
    if "github" in text or "repo" in text:
        return "github"
    if "gitlab" in text:
        return "gitlab"
    return "web"


def _build_cluster_text(finding: FindingResponse) -> str:
    return " | ".join(
        [
            finding.context_window or "",
            finding.pattern_type,
            finding.matched_value,
            finding.ai_label or "",
            finding.groq_summary or "",
        ]
    ).strip()


def _extract_keywords(texts: list[str]) -> list[str]:
    counts: Counter[str] = Counter()
    for text in texts:
        for token in TOKEN_RE.findall(text.lower()):
            if token in STOPWORDS or token.isdigit():
                continue
            counts[token] += 1

    return [token for token, _ in counts.most_common(6)]


def _token_set(text: str) -> set[str]:
    return {
        token
        for token in TOKEN_RE.findall(text.lower())
        if token not in STOPWORDS and not token.isdigit()
    }


def _jaccard_similarity(left: str, right: str) -> float:
    left_tokens = _token_set(left)
    right_tokens = _token_set(right)
    if not left_tokens and not right_tokens:
        return 1.0
    if not left_tokens or not right_tokens:
        return 0.0

    intersection = len(left_tokens & right_tokens)
    union = len(left_tokens | right_tokens)
    return round(intersection / union, 3) if union else 0.0


def _cluster_texts(texts: list[str], threshold: float = 0.32) -> list[list[int]]:
    if not texts:
        return []

    clusters: list[list[int]] = []
    assigned: set[int] = set()

    for index, text in enumerate(texts):
        if index in assigned:
            continue

        cluster = [index]
        assigned.add(index)
        for candidate in range(index + 1, len(texts)):
            if candidate in assigned:
                continue
            if _jaccard_similarity(text, texts[candidate]) >= threshold:
                cluster.append(candidate)
                assigned.add(candidate)
        clusters.append(cluster)

    return clusters


def _average_similarity(texts: list[str]) -> float:
    if len(texts) <= 1:
        return 1.0

    scores: list[float] = []
    for left in range(len(texts)):
        for right in range(left + 1, len(texts)):
            scores.append(_jaccard_similarity(texts[left], texts[right]))

    if not scores:
        return 1.0

    return round(sum(scores) / len(scores), 3)


def _severity_rank(severity: Severity) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 1)


def _highest_severity(severities: list[Severity]) -> Severity:
    if not severities:
        return "LOW"
    return max(severities, key=_severity_rank)


class InvestigationsService:
    """Builds the investigation timeline from findings and alerts."""

    def __init__(self) -> None:
        self._findings = FindingsService()

    async def fetch_timeline(
        self,
        range_key: TimelineRange = "30d",
        severity: Severity | None = None,
        group_by: TimelineGroupBy = "cluster",
    ) -> ThreatTimelineResponse:
        return await run_in_threadpool(self._fetch_timeline_sync, range_key, severity, group_by)

    def _fetch_all_findings(self, severity: Severity | None, cutoff: datetime | None) -> list[FindingResponse]:
        findings: list[FindingResponse] = []
        page = 1

        while True:
            response = self._findings.fetch_findings_sync(
                page=page,
                page_size=PAGE_SIZE,
                sort_by="created_at",
                sort_order="desc",
                severity=severity,
                search=None,
            )
            findings.extend(response.items)
            if not response.items or page >= response.total_pages:
                break

            if cutoff is not None and response.items:
                oldest = response.items[-1].created_at
                if oldest < cutoff:
                    break

            page += 1

        if cutoff is not None:
            findings = [finding for finding in findings if finding.created_at >= cutoff]

        return findings

    def _fetch_all_alerts(self, severity: Severity | None, cutoff: datetime | None) -> list[AlertResponse]:
        alerts: list[AlertResponse] = []
        page = 1

        while True:
            response = alert_service.fetch_alerts_sync(
                page=page,
                page_size=ALERT_PAGE_SIZE,
                severity=severity,
                status=None,
                search=None,
            )
            alerts.extend(response.items)
            if not response.items or page >= response.total_pages:
                break

            if cutoff is not None and response.items:
                oldest = response.items[-1].created_at
                if oldest < cutoff:
                    break

            page += 1

        if cutoff is not None:
            alerts = [alert for alert in alerts if alert.created_at >= cutoff]

        return alerts

    def _build_event(
        self,
        *,
        event_id: str,
        event_type: TimelineEventType,
        title: str,
        timestamp: datetime,
        severity: Severity,
        source_type: str,
        pattern_type: str | None = None,
        matched_value: str | None = None,
        finding_id: str | None = None,
        alert_id: str | None = None,
        cluster_id: str | None = None,
        summary: str | None = None,
        related_count: int = 0,
        target_domain_match: bool = False,
        unread: bool | None = None,
    ) -> TimelineEventResponse:
        return TimelineEventResponse(
            id=event_id,
            event_type=event_type,
            title=title,
            timestamp=timestamp,
            severity=severity,
            source_type=source_type,
            pattern_type=pattern_type,
            matched_value=matched_value,
            finding_id=finding_id,
            alert_id=alert_id,
            cluster_id=cluster_id,
            summary=summary,
            related_count=related_count,
            target_domain_match=target_domain_match,
            unread=unread,
        )

    def _fetch_timeline_sync(
        self,
        range_key: TimelineRange,
        severity: Severity | None,
        group_by: TimelineGroupBy,
    ) -> ThreatTimelineResponse:
        cutoff = _range_start(range_key)
        findings = self._fetch_all_findings(severity, cutoff)
        alerts = self._fetch_all_alerts(severity, cutoff)

        findings = sorted(findings, key=lambda finding: finding.created_at)
        finding_by_id = {finding.id: finding for finding in findings}

        cluster_inputs = [_build_cluster_text(finding) for finding in findings]
        cluster_indexes = _cluster_texts(cluster_inputs, threshold=0.32) if cluster_inputs else []

        clusters: list[TimelineClusterResponse] = []
        cluster_lookup: dict[str, TimelineClusterResponse] = {}
        finding_cluster_map: dict[str, str] = {}
        event_records: list[TimelineEventResponse] = []
        github_exposure_count = 0

        for cluster_number, indexes in enumerate(cluster_indexes, start=1):
            members = [findings[index] for index in indexes]
            if not members:
                continue

            cluster_id = f"cluster-{cluster_number}"
            member_ids = {finding.id for finding in members}
            source_types = sorted({(_guess_source_type(finding)) for finding in members})
            severities = [finding.severity for finding in members]
            severity_counts = {severity_name: 0 for severity_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            for item in members:
                severity_counts[item.severity] += 1
                finding_cluster_map[item.id] = cluster_id

            finding_texts = [_build_cluster_text(finding) for finding in members]
            shared_keywords = _extract_keywords(finding_texts)
            shared_indicators = sorted(
                {
                    _normalize_text(finding.pattern_type) for finding in members if _normalize_text(finding.pattern_type)
                }
                | {
                    _normalize_text(finding.matched_value) for finding in members if _normalize_text(finding.matched_value)
                }
            )[:6]
            average_risk_score = round(sum(finding.risk_score for finding in members) / len(members), 2)
            average_similarity = _average_similarity(finding_texts)
            first_seen = min(finding.created_at for finding in members)
            last_seen = max(finding.created_at for finding in members)
            cluster_alerts = [alert for alert in alerts if alert.finding_id in member_ids]
            alert_ids = [alert.id for alert in cluster_alerts]
            incident_count = 1 if any(finding.severity == "CRITICAL" for finding in members) or cluster_alerts else 0

            daily_counts: defaultdict[str, int] = defaultdict(int)
            for finding in members:
                daily_counts[finding.created_at.date().isoformat()] += 1
            timeline = [TimeSeriesPoint(date=date, count=count) for date, count in sorted(daily_counts.items())]

            dominant_source = Counter(source_types).most_common(1)[0][0] if source_types else "web"
            dominant_severity = _highest_severity(severities)
            indicator_label = shared_indicators[0] if shared_indicators else members[0].pattern_type
            label = f"{dominant_source.title()} {indicator_label}".strip()

            cluster_event_id = f"incident-{cluster_id}"
            incident_event = self._build_event(
                event_id=cluster_event_id,
                event_type="incident",
                title=f"Related incident: {label}",
                timestamp=first_seen,
                severity=dominant_severity,
                source_type=dominant_source,
                pattern_type=members[0].pattern_type,
                cluster_id=cluster_id,
                summary=f"{len(members)} related findings correlated into an incident review thread.",
                related_count=len(members),
                unread=False,
            )

            if incident_count:
                event_records.append(incident_event)

            cluster = TimelineClusterResponse(
                cluster_id=cluster_id,
                label=label,
                severity=dominant_severity,
                severity_counts=severity_counts,
                source_types=source_types,
                finding_count=len(members),
                alert_count=len(cluster_alerts),
                incident_count=incident_count,
                average_similarity=average_similarity,
                average_risk_score=average_risk_score,
                first_seen=first_seen,
                last_seen=last_seen,
                shared_keywords=shared_keywords,
                shared_indicators=shared_indicators,
                timeline=timeline,
                finding_ids=[finding.id for finding in members],
                alert_ids=alert_ids,
                incident_event_id=cluster_event_id if incident_count else None,
            )
            clusters.append(cluster)
            cluster_lookup[cluster_id] = cluster

        for finding in findings:
            cluster_id = finding_cluster_map.get(finding.id)
            source_type = _guess_source_type(finding)
            event_type: TimelineEventType = "github_exposure" if source_type == "github" else "finding"
            if event_type == "github_exposure":
                github_exposure_count += 1

            related_count = len(cluster_lookup[cluster_id].finding_ids) if cluster_id and cluster_id in cluster_lookup else 0
            event_records.append(
                self._build_event(
                    event_id=finding.id,
                    event_type=event_type,
                    title=f"{finding.severity.title()} {finding.pattern_type}",
                    timestamp=finding.created_at,
                    severity=finding.severity,
                    source_type=source_type,
                    pattern_type=finding.pattern_type,
                    matched_value=finding.matched_value,
                    finding_id=finding.id,
                    cluster_id=cluster_id,
                    summary=finding.reasoning_summary or finding.groq_summary or finding.context_window,
                    related_count=related_count,
                    target_domain_match=bool(
                        finding.classifier_metadata and isinstance(finding.classifier_metadata, dict) and finding.classifier_metadata.get("target_domain_match")
                    ),
                )
            )

        for alert in alerts:
            cluster_id = finding_cluster_map.get(alert.finding_id or "")
            linked_finding = finding_by_id.get(alert.finding_id or "")
            source_type = _guess_source_type(linked_finding) if linked_finding else "alert"
            if cluster_id and cluster_id in cluster_lookup:
                related_count = len(cluster_lookup[cluster_id].finding_ids)
            else:
                related_count = 0

            event_records.append(
                self._build_event(
                    event_id=alert.id,
                    event_type="alert",
                    title=alert.title,
                    timestamp=alert.created_at,
                    severity=alert.severity,
                    source_type=source_type,
                    pattern_type=alert.pattern_type,
                    matched_value=alert.matched_value,
                    finding_id=alert.finding_id,
                    alert_id=alert.id,
                    cluster_id=cluster_id,
                    summary=alert.message,
                    related_count=related_count,
                    target_domain_match=alert.target_domain_match,
                    unread=alert.status == "UNREAD",
                )
            )

        event_records = sorted(
            event_records,
            key=lambda item: (item.timestamp, _severity_rank(item.severity)),
        )
        clusters = sorted(clusters, key=lambda cluster: (cluster.first_seen, -cluster.finding_count))

        incident_count = sum(cluster.incident_count for cluster in clusters)
        total_events = len(event_records)

        if group_by == "cluster":
            clusters = sorted(clusters, key=lambda cluster: (-cluster.finding_count, cluster.first_seen))

        return ThreatTimelineResponse(
            range=range_key,
            group_by=group_by,
            severity_filter=severity,
            total_findings=len(findings),
            total_alerts=len(alerts),
            total_events=total_events,
            incident_count=incident_count,
            github_exposure_count=github_exposure_count,
            events=event_records,
            clusters=clusters,
        )


investigations_service = InvestigationsService()
