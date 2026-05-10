"""Contextual cybersecurity reasoning for DarkShield findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any


LOGGER = logging.getLogger(__name__)


@dataclass
class ReasoningResult:
    reasoning_summary: str
    attack_surface_assessment: str
    remediation_guidance: str
    confidence_explanation: str
    exposure_reasoning: str
    mitre_tags: list[str]
    metadata: dict[str, Any]


def _normalize(value: Any, default: str = "unknown") -> str:
    text = str(value or "").strip()
    return text or default


def _mitre_tags(ai_label: Any, pattern_type: Any, source_type: Any) -> list[str]:
    label = _normalize(ai_label).lower()
    pattern = _normalize(pattern_type).lower()
    source = _normalize(source_type).lower()

    tags: list[str] = []
    if label in {"credential_leak", "api_key_exposure"}:
        tags.append("T1552")
    if "secret" in pattern or "token" in pattern or "credential" in pattern:
        tags.append("T1552")
    if label == "infrastructure_exposure" or "infrastructure" in pattern or "hostname" in pattern:
        tags.append("T1590")
    if label == "suspicious_activity" or source in {"github", "gitlab"}:
        tags.append("T1213")
    if not tags:
        tags.append("T1595")

    return sorted(set(tags))


def generate_reasoning(
    ai_label: Any,
    severity: Any,
    pattern_type: Any,
    source_type: Any,
    risk_score: Any,
    context_window: Any,
) -> ReasoningResult:
    """Build concise analyst reasoning with ATT&CK-style context."""
    normalized_label = _normalize(ai_label)
    normalized_severity = _normalize(severity, "LOW").upper()
    normalized_pattern = _normalize(pattern_type)
    normalized_source = _normalize(source_type)
    normalized_score = int(risk_score or 0)
    attack_surface = (
        f"Exposure surfaced through {normalized_source} content and matches the {normalized_pattern} signal."
    )
    remediation = "Validate the indicator, rotate any exposed secrets, and scope the affected source for lateral spread."
    confidence = (
        f"Classifier confidence is reflected in the risk score {normalized_score};"
        f" severity resolved to {normalized_severity}."
    )
    exposure = (
        f"Finding classified as {normalized_label} with context: {str(context_window or '').strip()[:240]}"
        if normalized_label != "unknown"
        else f"Finding mapped to {normalized_pattern} with context: {str(context_window or '').strip()[:240]}"
    )
    mitre_tags = _mitre_tags(normalized_label, normalized_pattern, normalized_source)
    summary = (
        f"{normalized_severity} {normalized_pattern} exposure likely impacts the active attack surface "
        f"and should be reviewed as {', '.join(mitre_tags)}."
    )
    metadata = {
        "attack_surface_assessment": attack_surface,
        "remediation_guidance": remediation,
        "confidence_explanation": confidence,
        "exposure_reasoning": exposure,
        "source_type": normalized_source,
        "risk_score": normalized_score,
        "mitre_tags": mitre_tags,
    }
    LOGGER.debug("Generated reasoning metadata: %s", metadata)
    return ReasoningResult(
        reasoning_summary=summary,
        attack_surface_assessment=attack_surface,
        remediation_guidance=remediation,
        confidence_explanation=confidence,
        exposure_reasoning=exposure,
        mitre_tags=mitre_tags,
        metadata=metadata,
    )
