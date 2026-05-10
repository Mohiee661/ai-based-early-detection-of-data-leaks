"""Pattern extraction engine for DarkShield leaked-text analysis."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Pattern


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
CONTEXT_RADIUS = 100

PATTERNS: dict[str, Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "api_key": re.compile(r"\b(?:sk-[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{12,}|ghp_[A-Za-z0-9]{12,}|xoxb-[A-Za-z0-9-]{12,})\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1}\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
}


def mask_value(value: str) -> str:
    """Mask a sensitive value while preserving a small prefix and suffix."""
    if not value:
        return ""
    if len(value) <= 6:
        return f"{value[:4]}***{value[-2:]}"
    return f"{value[:4]}***{value[-2:]}"


def extract_context(text: str, start: int, end: int, radius: int = CONTEXT_RADIUS) -> str:
    """Return a context window around a matched span."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].strip()


def classify_confidence(pattern_type: str) -> str:
    """Assign a simple rule-based confidence level."""
    if pattern_type in {"api_key", "email"}:
        return "high"
    if pattern_type in {"credit_card", "phone"}:
        return "medium"
    if pattern_type == "ipv4":
        return "low"
    return "medium"


def _normalize_text(text: Any) -> str:
    """Safely normalize incoming text to a string."""
    if text is None:
        return ""
    if isinstance(text, str):
        return text
    try:
        return str(text)
    except Exception:
        LOGGER.exception("Failed to normalize malformed text input.")
        return ""


def extract_findings(text: Any) -> list[dict[str, str]]:
    """Extract cybersecurity indicators from a text blob."""
    normalized_text = _normalize_text(text)
    if not normalized_text:
        LOGGER.info("No text content available for pattern analysis.")
        return []

    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, int, int]] = set()

    for pattern_type, pattern in PATTERNS.items():
        LOGGER.info("Scanning for pattern type: %s", pattern_type)
        for match in pattern.finditer(normalized_text):
            matched_value = match.group(0)
            key = (pattern_type, matched_value.lower(), match.start(), match.end())
            if key in seen:
                continue

            seen.add(key)
            findings.append(
                {
                    "pattern_type": pattern_type,
                    "matched_value": mask_value(matched_value),
                    "context_window": extract_context(normalized_text, match.start(), match.end()),
                    "rule_confidence": classify_confidence(pattern_type),
                }
            )

    LOGGER.info("Pattern scan completed with %s finding(s).", len(findings))
    return findings


def analyze_text(text: Any) -> list[dict[str, str]]:
    """Compatibility wrapper for the DarkShield findings pipeline."""
    return extract_findings(text)


def _sample_text() -> str:
    """Provide a simple built-in example for manual testing."""
    return (
        "Forum drop from last night:\n"
        "user=analyst@example.com reported token sk-AbCdEfGh1234567890 and host 192.168.14.22.\n"
        "Mirror domain: breach-lab.example.org\n"
        "Operator note: validate access before reposting."
    )


# Unit-test style examples:
# assert classify_confidence("api_key") == "high"
# assert mask_value("analyst@example.com").startswith("anal")
# assert extract_findings("Contact user@example.com")[0]["pattern_type"] == "email"


if __name__ == "__main__":
    sample = _sample_text()
    results = extract_findings(sample)
    print("====================================")
    print("DARKSHIELD PATTERN ENGINE TEST")
    print("====================================")
    print(json.dumps(results, indent=2))
