"""Composite risk scoring for DarkShield findings."""

from __future__ import annotations

import json
import logging
from typing import Any


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)

SEVERITY_BOOSTS: dict[str, int] = {
    "api_key": 15,
    "credit_card": 12,
    "email": 8,
    "ipv4": 3,
}


def _safe_float(value: float | None) -> float | None:
    """Normalize an optional numeric input."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        LOGGER.warning("Invalid ai_confidence value received: %r", value)
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    """Normalize an integer-like input."""
    try:
        return int(value)
    except (TypeError, ValueError):
        LOGGER.warning("Invalid integer input received: %r", value)
        return default


def calculate_ai_contribution(ai_confidence: float | None) -> float:
    """Calculate the AI confidence contribution."""
    normalized = _safe_float(ai_confidence)
    if normalized is None:
        return 20.0
    normalized = max(0.0, min(normalized, 1.0))
    return normalized * 45


def calculate_pattern_contribution(pattern_count: int) -> float:
    """Calculate the pattern density contribution."""
    normalized_count = max(0, _safe_int(pattern_count))
    return min(normalized_count, 5) / 5 * 25


def calculate_recency_contribution(hours_since_found: int) -> float:
    """Calculate the recency contribution."""
    normalized_hours = max(0, _safe_int(hours_since_found))
    if normalized_hours < 24:
        return 20.0
    if normalized_hours < 168:
        return 14.0
    return 6.0


def calculate_domain_contribution(target_domain_match: bool) -> float:
    """Calculate the domain match contribution."""
    return 10.0 if bool(target_domain_match) else 0.0


def calculate_pattern_boost(pattern_type: str) -> float:
    """Return a boost based on the matched pattern type."""
    normalized_type = (pattern_type or "").strip().lower()
    return float(SEVERITY_BOOSTS.get(normalized_type, 0))


def map_severity(score: int) -> str:
    """Map a numeric score to a severity label."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def build_reason(
    pattern_type: str,
    score: int,
    severity: str,
    target_domain_match: bool,
    pattern_count: int,
) -> str:
    """Build a short human-readable explanation."""
    domain_note = "matched a target domain" if target_domain_match else "did not match a target domain"
    return (
        f"{pattern_type or 'unknown'} indicator scored {score} ({severity}) "
        f"with pattern_count={max(0, _safe_int(pattern_count))} and {domain_note}."
    )


def calculate_risk_score(
    ai_confidence: float | None,
    pattern_type: str,
    hours_since_found: int,
    target_domain_match: bool,
    pattern_count: int,
) -> dict[str, Any]:
    """Calculate a composite risk score for one finding."""
    ai_contribution = calculate_ai_contribution(ai_confidence)
    pattern_contribution = calculate_pattern_contribution(pattern_count)
    recency_contribution = calculate_recency_contribution(hours_since_found)
    domain_contribution = calculate_domain_contribution(target_domain_match)
    pattern_boost = calculate_pattern_boost(pattern_type)

    raw_score = (
        ai_contribution
        + pattern_contribution
        + recency_contribution
        + domain_contribution
        + pattern_boost
    )
    score = min(int(round(raw_score)), 100)
    severity = map_severity(score)

    result = {
        "score": score,
        "severity": severity,
        "breakdown": {
            "ai_contribution": ai_contribution,
            "pattern_contribution": pattern_contribution,
            "recency_contribution": recency_contribution,
            "domain_contribution": domain_contribution,
            "pattern_boost": pattern_boost,
        },
        "reason": build_reason(pattern_type, score, severity, target_domain_match, pattern_count),
    }
    LOGGER.info("Calculated risk score for pattern_type=%s: %s", pattern_type, score)
    return result


# Unit-test style examples:
# assert calculate_pattern_boost("api_key") == 15.0
# assert map_severity(81) == "CRITICAL"
# assert calculate_risk_score(None, "email", 12, False, 3)["score"] >= 0


def main() -> None:
    """Run sample risk score calculations."""
    samples = [
        {
            "ai_confidence": 0.92,
            "pattern_type": "api_key",
            "hours_since_found": 6,
            "target_domain_match": True,
            "pattern_count": 5,
        },
        {
            "ai_confidence": 0.58,
            "pattern_type": "email",
            "hours_since_found": 72,
            "target_domain_match": False,
            "pattern_count": 2,
        },
        {
            "ai_confidence": None,
            "pattern_type": "ipv4",
            "hours_since_found": 240,
            "target_domain_match": False,
            "pattern_count": 1,
        },
    ]

    print("====================================")
    print("DARKSHIELD RISK SCORER TEST")
    print("====================================")
    for index, sample in enumerate(samples, start=1):
        result = calculate_risk_score(**sample)
        print(f"[Sample {index}]")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
