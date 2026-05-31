from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq
from pydantic import BaseModel
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions


BACKEND_ROOT = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_ROOT.parent
for env_path in (BACKEND_ROOT / ".env", REPO_ROOT / ".env"):
    if env_path.exists():
        load_dotenv(env_path, override=False)


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
ALLOWED_ORIGINS = [origin.strip() for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


app = FastAPI(title="DarkShield Backend", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


PATTERNS: dict[str, tuple[str, str]] = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "HIGH"),
    "AWS Secret Key": (r"(?i)aws.{0,20}secret.{0,20}[\'\"][0-9a-zA-Z/+=]{40}[\'\"]", "CRITICAL"),
    "OpenAI Key": (r"sk-[a-zA-Z0-9]{32,}", "HIGH"),
    "Anthropic Key": (r"sk-ant-[a-zA-Z0-9\-]{90,}", "HIGH"),
    "Groq Key": (r"gsk_[a-zA-Z0-9]{50,}", "HIGH"),
    "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "HIGH"),
    "Stripe Secret": (r"sk_live_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Slack Token": (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "MEDIUM"),
    "Private Key": (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    "Generic Password": (r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?", "MEDIUM"),
    "Generic Secret": (r"(?i)(secret|api_key|api_secret|access_token)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?", "MEDIUM"),
}

SKIP_EXT = {
    ".png",
    ".jpg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".ttf",
    ".zip",
    ".pdf",
    ".lock",
    ".min.js",
    ".map",
    ".exe",
    ".bin",
}


class ScanRequest(BaseModel):
    repo_id: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_thinking(text: str) -> str:
    if "</thinking>" in text:
        return text.split("</thinking>", maxsplit=1)[-1].strip()
    return text.strip()


def _safe_repo_lookup(client: Client, repo_id: str) -> dict[str, Any]:
    response = client.table("repos").select("*").eq("id", repo_id).limit(1).execute()
    rows = getattr(response, "data", []) or []
    if not rows:
        raise HTTPException(status_code=404, detail="Repo not found")
    return rows[0]


def _parse_status(status: str | None) -> str:
    value = str(status or "").upper().strip()
    if value in {"PENDING", "SCANNING", "DONE", "ERROR"}:
        return value.lower()
    return "pending"


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _supabase_for_request(request: Request | None) -> Client:
    if request is not None:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", maxsplit=1)[1].strip()
            if token:
                return create_client(
                    SUPABASE_URL,
                    SUPABASE_KEY,
                    options=SyncClientOptions(
                        headers={"Authorization": f"Bearer {token}"},
                        auto_refresh_token=False,
                        persist_session=False,
                    ),
                )

    return supabase


def _should_skip_file(path: str, size: int | None) -> bool:
    if size is not None and size >= 300_000:
        return True
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in SKIP_EXT)


def _severity_rank(severity: str) -> int:
    mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return mapping.get(severity.upper(), 1)


def _build_reasoning(owner: str, name: str, findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No exposed secrets were detected in this repository scan."

    type_counts: dict[str, int] = {}
    for finding in findings:
        type_counts[finding["secret_type"]] = type_counts.get(finding["secret_type"], 0) + 1

    breakdown = ", ".join(f"{count}x {secret_type}" for secret_type, count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0])))
    critical_count = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    cross_repo = len({finding["secret_hash"] for finding in findings if finding.get("cluster_repo_count", 1) >= 2})

    prompt = (
        f"GitHub repo {owner}/{name} scan:\n"
        f"- Total secrets exposed: {len(findings)}\n"
        f"- Critical severity: {critical_count}\n"
        f"- Types: {breakdown}\n"
        f"- Also leaked in other monitored repos: {cross_repo}\n\n"
        "What is the risk level, what are the most urgent actions, and what does cross-repo leakage imply?"
    )

    if groq_client is None:
        return (
            f"Repository {owner}/{name} contains {len(findings)} exposed secret(s). "
            f"Critical findings: {critical_count}. Types: {breakdown}. "
            "Rotate exposed credentials, remove secrets from the repository history, and investigate cross-repo reuse."
        )

    try:
        chat = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior security analyst. Think step by step inside "
                        "<thinking> tags, then write a plain-English summary under 120 words."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=350,
        )
        raw = chat.choices[0].message.content or ""
        return _strip_thinking(raw)
    except Exception:
        return (
            f"Repository {owner}/{name} contains {len(findings)} exposed secret(s). "
            f"Critical findings: {critical_count}. Types: {breakdown}. "
            "Rotate exposed credentials, remove secrets from the repository history, and investigate cross-repo reuse."
        )


def _distinct_repo_count_for_hash(client: Client, secret_hash: str) -> int:
    response = client.table("findings").select("repo_id").eq("secret_hash", secret_hash).execute()
    rows = getattr(response, "data", []) or []
    return len({str(row.get("repo_id") or "") for row in rows if row.get("repo_id")})


def _aggregate_clusters(client: Client) -> list[dict[str, Any]]:
    response = client.table("findings").select("secret_hash,secret_type,severity,created_at,repo_id").execute()
    rows = getattr(response, "data", []) or []
    grouped: dict[str, dict[str, Any]] = {}

    for row in rows:
        secret_hash = str(row.get("secret_hash") or "").strip()
        if not secret_hash:
            continue

        group = grouped.setdefault(
            secret_hash,
            {
                "id": secret_hash,
                "secret_hash": secret_hash,
                "secret_type": row.get("secret_type") or "Unknown",
                "severity": row.get("severity") or "LOW",
                "repo_ids": set(),
                "created_at": row.get("created_at"),
            },
        )
        if row.get("repo_id"):
            group["repo_ids"].add(str(row["repo_id"]))
        if _severity_rank(str(row.get("severity") or "LOW")) > _severity_rank(str(group["severity"])):
            group["severity"] = row.get("severity") or group["severity"]
        if row.get("created_at") and (not group["created_at"] or str(row["created_at"]) < str(group["created_at"])):
            group["created_at"] = row.get("created_at")

    result: list[dict[str, Any]] = []
    for group in grouped.values():
        repo_ids = group.pop("repo_ids")
        repo_count = len(repo_ids)
        if repo_count < 2:
            continue
        group["repo_count"] = repo_count
        result.append(group)

    result.sort(key=lambda item: (item.get("repo_count", 0), item.get("created_at") or ""), reverse=True)
    return result


async def _scan_file(
    client: httpx.AsyncClient,
    owner: str,
    name: str,
    file_path: str,
    repo_id: str,
    findings: list[dict[str, Any]],
) -> None:
    raw_url = f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{file_path}"
    try:
        response = await client.get(raw_url, timeout=10)
        if response.status_code != 200:
            return

        lines = response.text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for secret_type, (pattern, severity) in PATTERNS.items():
                match = re.search(pattern, line)
                if not match:
                    continue
                secret_value = match.group(0)
                secret_hash = _hash_secret(secret_value)
                findings.append(
                    {
                        "repo_id": repo_id,
                        "file_path": file_path,
                        "line_number": line_number,
                        "secret_type": secret_type,
                        "severity": severity,
                        "snippet": line.strip()[:120],
                        "secret_hash": secret_hash,
                    }
                )
    except Exception:
        return


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_repo(req: ScanRequest, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, req.repo_id)
    owner = str(repo.get("owner") or "").strip()
    name = str(repo.get("name") or "").strip()
    github_url = str(repo.get("github_url") or "").strip()

    client.table("repos").update({"status": "scanning"}).eq("id", req.repo_id).execute()

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    findings_raw: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=30, headers=headers) as http_client:
            tree_resp = await http_client.get(
                f"https://api.github.com/repos/{owner}/{name}/git/trees/HEAD?recursive=1"
            )
            if tree_resp.status_code != 200:
                client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
                raise HTTPException(status_code=400, detail="Could not fetch repo. Is it public?")

            tree = tree_resp.json().get("tree", [])
            files = [
                item
                for item in tree
                if item.get("type") == "blob" and not _should_skip_file(str(item.get("path") or ""), item.get("size"))
            ]

            for file_item in files[:200]:
                await _scan_file(
                    client=http_client,
                    owner=owner,
                    name=name,
                    file_path=str(file_item.get("path") or ""),
                    repo_id=req.repo_id,
                    findings=findings_raw,
                )
    except HTTPException:
        raise
    except Exception as exc:
        client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
        raise HTTPException(status_code=500, detail=f"Repository scan failed: {type(exc).__name__}: {exc}") from exc

    seen: set[tuple[str, str, int]] = set()
    unique_findings: list[dict[str, Any]] = []
    for finding in findings_raw:
        key = (finding["secret_hash"], finding["file_path"], int(finding["line_number"]))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    for finding in unique_findings:
        finding["cluster_id"] = None

    if unique_findings:
        client.table("findings").upsert(
            unique_findings,
            on_conflict="repo_id,file_path,line_number,secret_hash",
        ).execute()

    findings_for_reasoning: list[dict[str, Any]] = []
    for finding in unique_findings:
        finding["cluster_repo_count"] = _distinct_repo_count_for_hash(client, finding["secret_hash"])
        findings_for_reasoning.append(finding)

    ai_reasoning = _build_reasoning(owner, name, findings_for_reasoning)

    client.table("repos").update(
        {
            "status": "done",
            "last_scanned_at": _now_iso(),
            "finding_count": len(unique_findings),
            "ai_reasoning": ai_reasoning,
        }
    ).eq("id", req.repo_id).execute()

    return {
        "repo_id": req.repo_id,
        "github_url": github_url,
        "total": len(unique_findings),
        "ai_reasoning": ai_reasoning,
    }


@app.get("/findings/{repo_id}")
async def get_findings(repo_id: str, request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    response = (
        client.table("findings")
        .select("*")
        .eq("repo_id", repo_id)
        .order("created_at", desc=True)
        .execute()
    )
    return getattr(response, "data", []) or []


@app.get("/clusters")
async def get_clusters(request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    return _aggregate_clusters(client)
