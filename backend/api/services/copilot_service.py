"""Analyst copilot service for DarkShield."""

from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

import requests
from fastapi.concurrency import run_in_threadpool

from api.schemas.auth import AuthUser
from api.schemas.copilot import CopilotMessage, CopilotRequest, CopilotResponse
from api.schemas.findings import FindingResponse
from api.services.findings_service import FindingsService


LOGGER = logging.getLogger(__name__)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 12
MAX_CONTEXT_MESSAGES = 6


@dataclass
class CopilotContext:
    analysis_type: str
    supporting_findings: list[FindingResponse]
    metrics: Any
    sources: list[str]
    prompt: str


def _normalize_question(question: str) -> str:
    cleaned = re.sub(r"[\r\n\t]+", " ", question).strip()
    return cleaned[:500]


def _sanitize_text(value: Any, limit: int = 1600) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _recent_messages(messages: list[CopilotMessage]) -> list[CopilotMessage]:
    return messages[-MAX_CONTEXT_MESSAGES:]


class CopilotService:
    def __init__(self) -> None:
        self._findings = FindingsService()
        self._request_windows: dict[str, deque[float]] = defaultdict(deque)

    def _check_rate_limit(self, user_key: str) -> None:
        now = time.time()
        window = self._request_windows[user_key]
        while window and now - window[0] > RATE_LIMIT_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= RATE_LIMIT_MAX_REQUESTS:
            raise ValueError("Rate limit exceeded. Please wait before sending another copilot request.")
        window.append(now)

    def _detect_analysis_type(self, question: str) -> str:
        lowered = question.lower()
        if any(term in lowered for term in ("critical", "sev 1", "sev1", "high-risk")):
            return "critical_leaks"
        if any(term in lowered for term in ("today", "today's", "summarize", "summary")):
            return "daily_summary"
        if any(term in lowered for term in ("api", "token", "key", "secret")):
            return "api_exposures"
        if any(term in lowered for term in ("github", "gitlab", "repository", "repo")):
            return "github_leaks"
        return "general_review"

    async def answer(self, payload: CopilotRequest, current_user: AuthUser) -> CopilotResponse:
        await run_in_threadpool(self._check_rate_limit, current_user.username)

        question = _normalize_question(payload.question)
        messages = _recent_messages(payload.messages)
        analysis_type = self._detect_analysis_type(question)

        metrics = await self._findings.fetch_dashboard_metrics()
        supporting_findings = await self._fetch_supporting_findings(question, analysis_type)
        prompt = self._build_prompt(question, messages, metrics, supporting_findings)
        answer = await self._generate_answer(prompt, question, analysis_type, metrics, supporting_findings)
        confidence = self._estimate_confidence(question, supporting_findings)

        return CopilotResponse(
            question=question,
            analysis_type=analysis_type,
            answer=answer,
            confidence=confidence,
            sources=["findings", "metrics", "analytics"],
            supporting_findings=supporting_findings,
            metrics=metrics,
            conversation=messages,
        )

    async def _fetch_supporting_findings(self, question: str, analysis_type: str) -> list[FindingResponse]:
        search_hint = self._extract_search_hint(question)
        if analysis_type == "critical_leaks":
            response = await self._findings.fetch_findings(
                page=1,
                page_size=8,
                sort_by="risk_score",
                sort_order="desc",
                severity="CRITICAL",
                search=search_hint,
            )
            return response.items

        if analysis_type == "api_exposures":
            response = await self._findings.fetch_findings(
                page=1,
                page_size=8,
                sort_by="risk_score",
                sort_order="desc",
                search=search_hint or "api",
            )
            return response.items

        if analysis_type == "daily_summary":
            response = await self._findings.fetch_findings(
                page=1,
                page_size=8,
                sort_by="created_at",
                sort_order="desc",
                search=search_hint,
            )
            return response.items

        if analysis_type == "github_leaks":
            response = await self._findings.fetch_findings(
                page=1,
                page_size=8,
                sort_by="risk_score",
                sort_order="desc",
                search=search_hint or "github",
            )
            return response.items

        response = await self._findings.fetch_findings(
            page=1,
            page_size=6,
            sort_by="risk_score",
            sort_order="desc",
            search=search_hint,
        )
        return response.items

    def _extract_search_hint(self, question: str) -> str | None:
        lowered = question.lower()
        for token in ("github", "gitlab", "api", "token", "key", "secret"):
            if token in lowered:
                return token
        return None

    def _build_prompt(
        self,
        question: str,
        messages: list[CopilotMessage],
        metrics: Any,
        findings: list[FindingResponse],
    ) -> str:
        conversation = "\n".join(f"{message.role}: {message.content}" for message in messages)
        finding_lines = "\n".join(
            (
                f"- {finding.severity} | {finding.pattern_type} | risk {finding.risk_score} | "
                f"{finding.ai_label or 'unclassified'} | {finding.groq_summary or finding.reasoning_summary or finding.matched_value}"
            )
            for finding in findings[:6]
        )
        return "\n".join(
            [
                "You are DarkShield's analyst copilot.",
                "Answer with concise, operational guidance. Avoid speculation.",
                f"Question: {question}",
                f"Conversation context:\n{conversation or 'none'}",
                (
                    "Metrics: "
                    f"total={metrics.total_findings}, critical={metrics.critical_findings}, "
                    f"high={metrics.high_findings}, today={metrics.findings_today}, api_exposures={metrics.api_key_exposures}"
                ),
                f"Relevant findings:\n{finding_lines or 'none'}",
                "Return a short answer and a direct next action recommendation.",
            ]
        )

    async def _generate_answer(
        self,
        prompt: str,
        question: str,
        analysis_type: str,
        metrics: Any,
        findings: list[FindingResponse],
    ) -> str:
        for provider, caller in (("groq", self._call_groq), ("openai", self._call_openai), ("ollama", self._call_ollama)):
            try:
                response = await run_in_threadpool(caller, prompt)
                if response:
                    return self._sanitize_answer(response)
            except Exception as exc:
                LOGGER.warning("%s copilot generation failed: %s", provider, exc)

        return self._deterministic_answer(question, analysis_type, metrics, findings)

    def _sanitize_answer(self, text: str) -> str:
        normalized = re.sub(r"\s+", " ", text).strip()
        return normalized[:2000]

    def _deterministic_answer(
        self,
        question: str,
        analysis_type: str,
        metrics: Any,
        findings: list[FindingResponse],
    ) -> str:
        if not findings:
            return (
                f"No supporting findings matched '{question}'. "
                f"Current totals show {metrics.critical_findings} critical findings and "
                f"{metrics.api_key_exposures} API-related exposures."
            )

        headline = findings[0]
        lines = [
            f"Analysis type: {analysis_type.replace('_', ' ')}.",
            (
                f"I found {len(findings)} supporting findings. "
                f"The highest-risk item is {headline.severity} {headline.pattern_type} "
                f"with risk {headline.risk_score}."
            ),
        ]

        if headline.groq_summary:
            lines.append(f"Summary: {headline.groq_summary}")
        elif headline.reasoning_summary:
            lines.append(f"Reasoning: {headline.reasoning_summary}")

        lines.append(
            "Recommended action: validate the exposed indicator, scope the affected source, and rotate or revoke any secrets if confirmed."
        )
        return " ".join(lines)

    def _estimate_confidence(self, question: str, findings: list[FindingResponse]) -> float:
        base = 0.55
        if findings:
            base += min(0.25, len(findings) * 0.04)
        if any(term in question.lower() for term in ("critical", "api", "github", "token", "secret")):
            base += 0.1
        return max(0.0, min(1.0, base))

    def _call_openai(self, prompt: str) -> str | None:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return None

        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity analyst."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 240,
            },
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_groq(self, prompt: str) -> str | None:
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key:
            return None

        model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip() or "llama-3.1-8b-instant"
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity analyst."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 240,
            },
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_ollama(self, prompt: str) -> str | None:
        base_url = os.getenv("OLLAMA_BASE_URL", "").strip()
        if not base_url:
            return None

        model = os.getenv("OLLAMA_MODEL", "llama3.1").strip() or "llama3.1"
        response = requests.post(
            f"{base_url.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response")


copilot_service = CopilotService()
