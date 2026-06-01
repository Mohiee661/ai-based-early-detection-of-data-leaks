from __future__ import annotations

import hashlib
import hmac
import os
import re
import smtplib
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
import math

import httpx
from cryptography.fernet import Fernet
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
HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "").strip()
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "").strip()

# Initialize Fernet cipher (generate key if not provided)
if not ENCRYPTION_KEY:
    _cipher_suite = Fernet(Fernet.generate_key())
    ENCRYPTION_KEY = _cipher_suite.key.decode("utf-8")
else:
    try:
        _cipher_suite = Fernet(ENCRYPTION_KEY.encode("utf-8"))
    except Exception:
        _cipher_suite = Fernet(Fernet.generate_key())
        ENCRYPTION_KEY = _cipher_suite.key.decode("utf-8")
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = "".join(os.environ.get("SMTP_PASSWORD", "").split())
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "15"))
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "").strip()
ALERT_EMAIL_TO = [
    recipient.strip()
    for recipient in os.environ.get("ALERT_EMAIL_TO", "").split(",")
    if recipient.strip()
]
ALLOWED_ORIGINS = [origin.strip() for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def debug_log(*args, **kwargs):
    """Print with automatic flush for logging"""
    print(*args, **kwargs, file=sys.stderr, flush=True)
    sys.stdout.flush()


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


def _hmac_sha256_hex(message: str) -> str:
    if HMAC_SECRET_KEY:
        return hmac.new(HMAC_SECRET_KEY.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def _hash_secret(secret: str) -> str:
    return _hmac_sha256_hex(secret)


def _encrypt_snippet(plaintext: str) -> str:
    """Encrypt snippet using Fernet (AES-128-CBC + HMAC)."""
    try:
        cipher_suite = Fernet(ENCRYPTION_KEY.encode("utf-8"))
        encrypted = cipher_suite.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")
    except Exception:
        return plaintext


def _decrypt_snippet(ciphertext: str) -> str:
    """Decrypt snippet using Fernet."""
    if not ciphertext:
        return ""
    try:
        cipher_suite = Fernet(ENCRYPTION_KEY.encode("utf-8"))
        decrypted = cipher_suite.decrypt(ciphertext.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception:
        return ciphertext


async def _get_first_commit_date(
    client: httpx.AsyncClient,
    owner: str,
    name: str,
    file_path: str,
) -> tuple[datetime | None, int]:
    """
    Get the first commit date of a file using GitHub API.
    Returns (first_commit_date, exposure_days).
    """
    try:
        # Use GitHub API to get commit history for this file.
        # Page 1 is the newest commit, so follow the last pagination link
        # when available to reach the oldest commit.
        url = f"https://api.github.com/repos/{owner}/{name}/commits"
        headers = {"Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        response = await client.get(
            url,
            headers=headers,
            params={"path": file_path, "per_page": 1, "page": 1},
            timeout=10,
        )
        if response.status_code != 200:
            print(f"WARNING: GitHub API returned {response.status_code} for {owner}/{name}/{file_path}")
            return None, 0

        history_response = response
        last_link = response.links.get("last")
        if last_link and last_link.get("url"):
            history_response = await client.get(last_link["url"], headers=headers, timeout=10)
            if history_response.status_code != 200:
                print(f"WARNING: GitHub API last-page lookup failed for {owner}/{name}/{file_path}")
                return None, 0

        commits = history_response.json()
        if not commits or not isinstance(commits, list):
            print(f"WARNING: No commits found for {file_path}")
            return None, 0

        oldest_commit = commits[0] if commits else None
        if not oldest_commit:
            return None, 0

        commit_meta = oldest_commit.get("commit", {}) if isinstance(oldest_commit, dict) else {}
        commit_date_str = (
            commit_meta.get("committer", {}).get("date")
            or commit_meta.get("author", {}).get("date")
        )
        if not commit_date_str:
            print(f"WARNING: No commit date found for {file_path}")
            return None, 0
        
        # Parse ISO format date
        first_commit_dt = datetime.fromisoformat(commit_date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        exposure_days = max(0, (now - first_commit_dt).days)
        
        print(f"OK: Exposure calculated for {file_path} ({exposure_days} days)")
        return first_commit_dt, exposure_days
    except Exception as e:
        print(f"WARNING: Error calculating exposure for {file_path}: {e}")
        return None, 0


def _calculate_exposure_score(severity: str, exposure_days: int) -> float:
    """
    Calculate exposure score using formula: severity_rank × log₂(days + 2).
    Higher score = longer exposure + higher severity.
    """
    severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severity_rank = severity_map.get(str(severity).upper(), 1)
    
    if exposure_days < 0:
        exposure_days = 0
    
    # Log base 2 of (days + 2) to avoid log(0)
    exposure_multiplier = math.log2(exposure_days + 2)

    return round(severity_rank * exposure_multiplier, 2)


async def _hydrate_missing_exposure_fields(
    client: Client,
    owner: str,
    name: str,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Backfill exposure fields for findings that predate the scoring migration.

    This keeps the UI populated even when older rows were inserted before
    exposure tracking existed or when a previous scan could not resolve history.
    """
    pending = [
        finding
        for finding in findings
        if finding.get("first_commit_date") is None or finding.get("exposure_days") is None or finding.get("exposure_score") is None
    ]
    if not pending:
        return findings

    async with httpx.AsyncClient(timeout=30) as http_client:
        for finding in pending:
            file_path = str(finding.get("file_path") or "").strip()
            if not file_path:
                continue

            first_commit_date, exposure_days = await _get_first_commit_date(http_client, owner, name, file_path)
            if first_commit_date is None:
                continue

            exposure_score = _calculate_exposure_score(str(finding.get("severity") or "LOW"), exposure_days)
            patch = {
                "first_commit_date": first_commit_date.isoformat(),
                "exposure_days": exposure_days,
                "exposure_score": exposure_score,
            }

            finding.update(patch)
            try:
                if finding.get("id"):
                    supabase.table("findings").update(patch).eq("id", finding["id"]).execute()
            except Exception as exc:
                print(f"WARNING: Failed to backfill exposure fields for {file_path}: {exc}")

    return findings


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


def _mail_alerts_enabled() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL_TO)


def _critical_alert_signature(repo_id: str, critical_findings: list[dict[str, Any]]) -> str:
    digest_source = "|".join(
        [repo_id, *sorted(finding["secret_hash"] for finding in critical_findings if finding.get("secret_hash"))]
    )
    return _hmac_sha256_hex(digest_source)


def _critical_alert_subject(owner: str, name: str, critical_count: int) -> str:
    return f"[DarkShield] {critical_count} critical finding(s) in {owner}/{name}"


def _critical_alert_body(
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
) -> str:
    lines = [
        "DarkShield critical alert",
        "",
        f"Repository: {owner}/{name}",
        f"Repository URL: {repo_url}",
        f"Total findings: {total_count}",
        f"Critical findings: {len(critical_findings)}",
        "",
        "Critical finding details:",
    ]

    for index, finding in enumerate(critical_findings[:10], start=1):
        lines.append(
            f"{index}. {finding['secret_type']} | {finding['file_path']}:{finding['line_number']} | {finding['snippet']}"
        )

    if len(critical_findings) > 10:
        lines.append(f"... and {len(critical_findings) - 10} more critical finding(s)")

    if ai_reasoning:
        lines.extend(["", "AI summary:", ai_reasoning])

    lines.extend(
        [
            "",
            "Immediate response:",
            "- Rotate exposed secrets",
            "- Revoke any public or shared credentials",
            "- Review commit history and remove hardcoded values",
        ]
    )
    return "\n".join(lines)


def _build_critical_alert_message(
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
) -> EmailMessage:
    from_address = ALERT_EMAIL_FROM or SMTP_USER or "darkshield@localhost"
    message = EmailMessage()
    message["Subject"] = _critical_alert_subject(owner, name, len(critical_findings))
    message["From"] = from_address
    message["To"] = ", ".join(ALERT_EMAIL_TO)
    message.set_content(
        _critical_alert_body(owner, name, repo_url, critical_findings, ai_reasoning, total_count)
    )
    return message


def _deliver_email(message: EmailMessage) -> None:
    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
                if SMTP_USER and SMTP_PASSWORD:
                    smtp.login(SMTP_USER, SMTP_PASSWORD)
                smtp.send_message(message)
            print(f"OK: Email sent successfully to {message['To']}")
            return

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)
        print(f"OK: Email sent successfully to {message['To']}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"ERROR: SMTP Authentication Failed: {e}")
        print("Check SMTP_USER and SMTP_PASSWORD in .env")
        raise
    except smtplib.SMTPException as e:
        print(f"ERROR: SMTP Error: {e}")
        raise
    except Exception as e:
        print(f"ERROR: Email delivery failed: {e}")
        raise


def _critical_alert_already_sent(client: Client, repo_id: str, scan_signature: str) -> bool:
    response = (
        client.table("critical_alert_notifications")
        .select("id")
        .eq("repo_id", repo_id)
        .eq("scan_signature", scan_signature)
        .eq("delivery_status", "sent")
        .limit(1)
        .execute()
    )
    rows = getattr(response, "data", []) or []
    return bool(rows)


def _record_critical_alert(
    client: Client,
    repo_id: str,
    scan_signature: str,
    critical_count: int,
    total_count: int,
    recipients: list[str],
    delivery_status: str,
    error_message: str | None = None,
) -> None:
    payload = {
        "repo_id": repo_id,
        "scan_signature": scan_signature,
        "critical_count": critical_count,
        "total_count": total_count,
        "recipients": recipients,
        "delivery_status": delivery_status,
        "error_message": error_message,
    }
    client.table("critical_alert_notifications").upsert(
        payload,
        on_conflict="repo_id,scan_signature",
    ).execute()


def _send_critical_mail(
    client: Client,
    repo_id: str,
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
) -> tuple[bool, str | None]:
    if not _mail_alerts_enabled():
        debug_log("SKIP: Email alerts disabled (SMTP_HOST, SMTP_USER, SMTP_PASSWORD, or ALERT_EMAIL_TO not set)")
        return False, "Email alerts are disabled or misconfigured."
    
    if not critical_findings:
        debug_log("SKIP: No critical findings to alert on")
        return False, "No critical findings to alert on."

    scan_signature = _critical_alert_signature(repo_id, critical_findings)
    if _critical_alert_already_sent(client, repo_id, scan_signature):
        debug_log(f"SKIP: Critical alert already sent for {owner}/{name}")
        return False, "A critical alert for this exact finding set was already sent."

    try:
        debug_log(f"EMAIL: Preparing critical alert email for {owner}/{name} ({len(critical_findings)} critical findings)")
        message = _build_critical_alert_message(
            owner=owner,
            name=name,
            repo_url=repo_url,
            critical_findings=critical_findings,
            ai_reasoning=ai_reasoning,
            total_count=total_count,
        )
        debug_log(f"EMAIL: Delivering email to: {ALERT_EMAIL_TO}")
        _deliver_email(message)
        _record_critical_alert(
            client=client,
            repo_id=repo_id,
            scan_signature=scan_signature,
            critical_count=len(critical_findings),
            total_count=total_count,
            recipients=ALERT_EMAIL_TO,
            delivery_status="sent",
        )
        debug_log("OK: Critical alert recorded as sent")
        return True, None
    except Exception as exc:
        debug_log(f"ERROR: Critical alert failed: {type(exc).__name__}: {exc}")
        import traceback
        debug_log(traceback.format_exc())
        try:
            _record_critical_alert(
                client=client,
                repo_id=repo_id,
                scan_signature=scan_signature,
                critical_count=len(critical_findings),
                total_count=total_count,
                recipients=ALERT_EMAIL_TO,
                delivery_status="failed",
                error_message=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
        return False, f"{type(exc).__name__}: {exc}"


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

        # Get first commit date for this file (for exposure duration scoring)
        first_commit_date, exposure_days = await _get_first_commit_date(client, owner, name, file_path)

        lines = response.text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for secret_type, (pattern, severity) in PATTERNS.items():
                match = re.search(pattern, line)
                if not match:
                    continue
                secret_value = match.group(0)
                secret_hash = _hash_secret(secret_value)
                
                # Encrypt the snippet
                plain_snippet = line.strip()[:120]
                encrypted_snippet = _encrypt_snippet(plain_snippet)
                
                # Calculate exposure score (default to 0 if no first_commit_date)
                exposure_score = _calculate_exposure_score(severity, exposure_days) if first_commit_date else None
                
                finding = {
                    "repo_id": repo_id,
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_type": secret_type,
                    "severity": severity,
                    "snippet": plain_snippet,
                    "snippet_enc": encrypted_snippet,
                    "secret_hash": secret_hash,
                }
                
                # Add exposure data if available
                if first_commit_date:
                    finding["first_commit_date"] = first_commit_date.isoformat()
                    finding["exposure_days"] = exposure_days
                    finding["exposure_score"] = exposure_score
                
                findings.append(finding)
    except Exception as e:
        print(f"WARNING: Error scanning {file_path}: {e}")
        return


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_repo(req: ScanRequest, request: Request) -> dict[str, Any]:
    print(f"\nSCAN: Starting scan for repo ID: {req.repo_id}")
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, req.repo_id)
    owner = str(repo.get("owner") or "").strip()
    name = str(repo.get("name") or "").strip()
    github_url = str(repo.get("github_url") or "").strip()

    print(f"SCAN: {owner}/{name}")
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
                print(f"ERROR: Failed to fetch repo tree: {tree_resp.status_code}")
                client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
                raise HTTPException(status_code=400, detail="Could not fetch repo. Is it public?")

            tree = tree_resp.json().get("tree", [])
            files = [
                item
                for item in tree
                if item.get("type") == "blob" and not _should_skip_file(str(item.get("path") or ""), item.get("size"))
            ]

            print(f"SCAN: Scanning {len(files)} files...")
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
        print(f"ERROR: Scan failed: {exc}")
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

    print(f"OK: Found {len(unique_findings)} unique secrets")

    for finding in unique_findings:
        finding["cluster_id"] = None

    if unique_findings:
        print("DB: Saving findings to database...")
        client.table("findings").upsert(
            unique_findings,
            on_conflict="repo_id,file_path,line_number,secret_hash",
        ).execute()
        print("OK: Findings saved")

    findings_for_reasoning: list[dict[str, Any]] = []
    for finding in unique_findings:
        finding["cluster_repo_count"] = _distinct_repo_count_for_hash(client, finding["secret_hash"])
        findings_for_reasoning.append(finding)

    print("AI: Generating AI reasoning...")
    ai_reasoning = _build_reasoning(owner, name, findings_for_reasoning)
    critical_findings = [finding for finding in unique_findings if str(finding.get("severity") or "").upper() == "CRITICAL"]
    print(f"ALERT: Critical findings: {len(critical_findings)}")
    
    mail_sent, mail_error = _send_critical_mail(
        client,
        req.repo_id,
        owner,
        name,
        github_url,
        critical_findings,
        ai_reasoning,
        len(unique_findings),
    )

    client.table("repos").update(
        {
            "status": "done",
            "last_scanned_at": _now_iso(),
            "finding_count": len(unique_findings),
            "ai_reasoning": ai_reasoning,
        }
    ).eq("id", req.repo_id).execute()

    print(f"OK: Scan complete for {owner}/{name}")

    return {
        "repo_id": req.repo_id,
        "github_url": github_url,
        "total": len(unique_findings),
        "ai_reasoning": ai_reasoning,
        "critical_alerts_enabled": _mail_alerts_enabled(),
        "critical_alert_email_sent": mail_sent,
        "critical_alert_error": mail_error,
        "critical_findings": len(critical_findings),
    }


@app.delete("/repos/{repo_id}")
async def delete_repo(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    client.table("repos").delete().eq("id", repo_id).execute()
    return {
        "deleted": True,
        "repo_id": repo_id,
        "github_url": repo.get("github_url"),
        "owner": repo.get("owner"),
        "name": repo.get("name"),
    }


@app.get("/findings/{repo_id}")
async def get_findings(repo_id: str, request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    response = (
        client.table("findings")
        .select("*")
        .eq("repo_id", repo_id)
        .order("created_at", desc=True)
        .execute()
    )
    findings = getattr(response, "data", []) or []
    
    # Decrypt snippets on retrieval
    for finding in findings:
        if finding.get("snippet_enc"):
            finding["snippet"] = _decrypt_snippet(finding["snippet_enc"])
        # Include exposure duration and score in response for older rows too.
        if finding.get("exposure_days") is None and finding.get("first_commit_date"):
            first_commit = datetime.fromisoformat(finding["first_commit_date"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            exposure_days = max(0, (now - first_commit).days)
            finding["exposure_days"] = exposure_days
            finding["exposure_score"] = _calculate_exposure_score(finding.get("severity", "LOW"), exposure_days)

    findings = await _hydrate_missing_exposure_fields(client, str(repo.get("owner") or ""), str(repo.get("name") or ""), findings)

    return findings


@app.get("/clusters")
async def get_clusters(request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    return _aggregate_clusters(client)
