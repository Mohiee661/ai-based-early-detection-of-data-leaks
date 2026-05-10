"""Threat summarization helpers for DarkShield."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import requests


LOGGER = logging.getLogger(__name__)


@dataclass
class SummaryResult:
    summary: str
    exposure_explanation: str
    recommendation: str
    source: str


def _truncate(value: Any, limit: int = 1200) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _build_prompt(context_window: Any, pattern_type: Any, severity: Any, risk_score: Any) -> str:
    return (
        "You are a cybersecurity analyst writing concise analyst notes.\n"
        f"Pattern type: {_truncate(pattern_type, 80)}\n"
        f"Severity: {_truncate(severity, 24)}\n"
        f"Risk score: {_truncate(risk_score, 12)}\n"
        f"Context window: {_truncate(context_window)}\n"
        "Return three short sections: summary, explanation, recommendation."
    )


def _deterministic_summary(context_window: Any, pattern_type: Any, severity: Any, risk_score: Any) -> SummaryResult:
    normalized_severity = str(severity or "LOW").upper()
    pattern = str(pattern_type or "unknown").replace("_", " ")
    summary = f"{normalized_severity} {pattern} signal with risk score {risk_score}."
    explanation = (
        f"The matched context suggests a {pattern} exposure. "
        f"Observed text: {_truncate(context_window, 220)}"
    )
    recommendation = "Review the source, confirm whether the indicator is real, and rotate or revoke secrets if confirmed."
    return SummaryResult(summary=summary, exposure_explanation=explanation, recommendation=recommendation, source="fallback")


def _call_openai(prompt: str) -> str | None:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 220,
    }
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def _call_groq(prompt: str) -> str | None:
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return None

    model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip() or "llama-3.1-8b-instant"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 220,
    }
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def _call_ollama(prompt: str) -> str | None:
    base_url = os.getenv("OLLAMA_BASE_URL", "").strip()
    if not base_url:
        return None

    model = os.getenv("OLLAMA_MODEL", "llama3.1").strip() or "llama3.1"
    payload = {"model": model, "prompt": prompt, "stream": False}
    response = requests.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=20)
    if response.status_code >= 400:
        return None
    data = response.json()
    return data.get("response")


def _split_response(text: str) -> tuple[str, str, str]:
    parts = [line.strip() for line in text.splitlines() if line.strip()]
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], parts[1]
    if len(parts) == 1:
        return parts[0], parts[0], parts[0]
    return text.strip(), text.strip(), text.strip()


def generate_summary(context_window: Any, pattern_type: Any, severity: Any, risk_score: Any) -> SummaryResult:
    prompt = _build_prompt(context_window, pattern_type, severity, risk_score)
    for provider, caller in (("groq", _call_groq), ("openai", _call_openai), ("ollama", _call_ollama)):
        try:
            response = caller(prompt)
            if response:
                summary, explanation, recommendation = _split_response(response)
                return SummaryResult(
                    summary=summary,
                    exposure_explanation=explanation,
                    recommendation=recommendation,
                    source=provider,
                )
        except Exception as exc:
            LOGGER.warning("%s summary generation failed: %s", provider, exc)

    return _deterministic_summary(context_window, pattern_type, severity, risk_score)
