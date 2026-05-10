"""Process raw leak pages into structured findings for DarkShield."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import get_supabase  # noqa: E402
from app.ai.classifier import get_classifier  # noqa: E402
from app.ai.explainability import generate_explanation  # noqa: E402
from app.ai.reasoning import generate_reasoning  # noqa: E402
from app.ai.summarizer import generate_summary  # noqa: E402
from app.ai.clustering import build_embedding_metadata  # noqa: E402
from app.pattern_engine import analyze_text  # noqa: E402
from app.risk_scorer import calculate_risk_score  # noqa: E402
from api.services.alerts_service import alert_service  # noqa: E402


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)
RAW_PAGES_TABLE = "raw_pages"
FINDINGS_TABLE = "findings"
SCAN_TARGETS_TABLE = "scan_targets"
RAW_PAGE_LIMIT = 50
BATCH_SIZE = 25
FALLBACK_RISK_SCORE = 0
FALLBACK_SEVERITY = "LOW"
CRITICAL_AI_LABELS = {"credential_leak", "api_key_exposure", "infrastructure_exposure"}


def fetch_raw_pages(limit: int = RAW_PAGE_LIMIT) -> list[dict[str, Any]]:
    """Fetch the newest raw page records from Supabase."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client unavailable while fetching raw pages.")
        return []

    try:
        response = (
            client.table(RAW_PAGES_TABLE)
            .select("id, url, raw_text, fetched_at")
            .order("fetched_at", desc=True)
            .limit(limit)
            .execute()
        )
        pages = getattr(response, "data", []) or []
        LOGGER.info("Fetched %s raw page(s) from `%s`.", len(pages), RAW_PAGES_TABLE)
        return pages
    except Exception as exc:
        LOGGER.exception("Failed to fetch raw pages: %s", exc)
        print(f"[ERROR] Failed to fetch raw pages: {exc}")
        return []


def fetch_target_domains() -> list[str]:
    """Fetch active target domains used for domain matching."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client unavailable while fetching target domains.")
        return []

    try:
        response = (
            client.table(SCAN_TARGETS_TABLE)
            .select("domain")
            .eq("is_active", True)
            .execute()
        )
        rows = getattr(response, "data", []) or []
        domains = [str(row.get("domain", "")).strip().lower() for row in rows if row.get("domain")]
        LOGGER.info("Fetched %s active target domain(s).", len(domains))
        return domains
    except Exception as exc:
        LOGGER.exception("Failed to fetch target domains: %s", exc)
        print(f"[WARNING] Failed to fetch target domains: {exc}")
        return []


def finding_exists(raw_page_id: str, pattern_type: str, matched_value: str) -> dict[str, Any] | None:
    """Return an existing finding row when one has already been inserted."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client unavailable while checking for duplicate findings.")
        return None

    try:
        response = (
            client.table(FINDINGS_TABLE)
            .select("id, risk_score, severity")
            .eq("raw_page_id", raw_page_id)
            .eq("pattern_type", pattern_type)
            .eq("matched_value", matched_value)
            .limit(1)
            .execute()
        )
        data = getattr(response, "data", []) or []
        return data[0] if data else None
    except Exception as exc:
        LOGGER.exception("Duplicate check failed for raw_page_id=%s: %s", raw_page_id, exc)
        print(f"[WARNING] Duplicate check failed for raw_page_id={raw_page_id}: {exc}")
        return None


def calculate_hours_since_found(fetched_at: Any) -> int:
    """Calculate age in hours from a raw page timestamp."""
    if not fetched_at:
        return 0

    try:
        parsed = datetime.fromisoformat(str(fetched_at).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
        return max(0, int(delta.total_seconds() // 3600))
    except Exception as exc:
        LOGGER.warning("Unable to parse fetched_at=%r: %s", fetched_at, exc)
        return 0


def _extract_hostname(url: Any) -> str:
    """Extract a lowercase hostname from a URL-like value."""
    if not url:
        return ""

    try:
        parsed = urlparse(str(url))
        return (parsed.hostname or "").lower()
    except Exception as exc:
        LOGGER.warning("Unable to parse url=%r: %s", url, exc)
        return ""


def calculate_target_domain_match(
    raw_page: dict[str, Any],
    finding: dict[str, str],
    target_domains: list[str],
) -> bool:
    """Check whether the finding appears related to any active target domain."""
    if not target_domains:
        return False

    hostname = _extract_hostname(raw_page.get("url"))
    haystack = " ".join(
        [
            hostname,
            str(raw_page.get("raw_text", "")).lower(),
            str(finding.get("matched_value", "")).lower(),
            str(finding.get("context_window", "")).lower(),
        ]
    )
    return any(domain and domain in haystack for domain in target_domains)


def build_finding_record(
    raw_page: dict[str, Any],
    finding: dict[str, str],
    pattern_count: int,
    target_domain_match: bool,
    hours_since_found: int,
) -> dict[str, Any]:
    """Convert one extracted finding into the findings table schema."""
    risk_score_value = FALLBACK_RISK_SCORE
    severity_value = FALLBACK_SEVERITY

    try:
        score_payload = calculate_risk_score(
            ai_confidence=None,
            pattern_type=finding["pattern_type"],
            hours_since_found=hours_since_found,
            target_domain_match=target_domain_match,
            pattern_count=pattern_count,
        )
        risk_score_value = int(score_payload.get("score", FALLBACK_RISK_SCORE))
        severity_value = str(score_payload.get("severity", FALLBACK_SEVERITY)).upper()
        LOGGER.info("[SUCCESS] Risk score calculated")
        LOGGER.info("[INFO] Severity assigned: %s", severity_value)
    except Exception as exc:
        LOGGER.exception("Risk score calculation failed: %s", exc)
        print(f"[WARNING] Risk scoring failed; using fallback values: {exc}")

    return {
        "raw_page_id": raw_page["id"],
        "pattern_type": finding["pattern_type"],
        "matched_value": finding["matched_value"],
        "context_window": finding["context_window"],
        "ai_label": None,
        "ai_confidence": None,
        "groq_summary": None,
        "shap_explanation": None,
        "reasoning_summary": None,
        "embedding_metadata": None,
        "classifier_metadata": None,
        "risk_score": risk_score_value,
        "severity": severity_value,
        "target_domain_match": target_domain_match,
    }


def enrich_with_ai(finding: dict[str, Any]) -> dict[str, Any]:
    """Run the lightweight AI classifier and return enrichment payload."""
    try:
        classifier = get_classifier()
        prediction = classifier.predict(
            finding.get("context_window"),
            finding.get("pattern_type"),
            finding.get("matched_value"),
        )
        label = prediction.label
        confidence = round(float(prediction.confidence), 4)
        metadata = {
            "model_path": str(classifier.model_path),
            "labels": classifier.metadata.get("labels", []),
            "probabilities": prediction.probabilities,
        }
        LOGGER.info("AI classified finding as %s (confidence=%.3f).", label, confidence)
        return {
            "ai_label": label,
            "ai_confidence": confidence,
            "classifier_metadata": metadata,
        }
    except Exception as exc:
        LOGGER.exception("AI enrichment failed: %s", exc)
        return {
            "ai_label": None,
            "ai_confidence": None,
            "classifier_metadata": None,
        }


def enrich_with_threat_summary(finding: dict[str, Any], risk_score: int) -> dict[str, Any]:
    """Create an analyst-friendly summary with graceful fallback handling."""
    try:
        summary = generate_summary(
            context_window=finding.get("context_window"),
            pattern_type=finding.get("pattern_type"),
            severity=finding.get("severity"),
            risk_score=risk_score,
        )
        return {
            "groq_summary": summary.summary,
            "classifier_metadata": {
                "summary_explanation": summary.exposure_explanation,
                "summary_recommendation": summary.recommendation,
                "summary_source": summary.source,
            },
        }
    except Exception as exc:
        LOGGER.exception("Threat summary generation failed: %s", exc)
        return {
            "groq_summary": None,
            "classifier_metadata": None,
        }


def enrich_with_reasoning(finding: dict[str, Any]) -> dict[str, Any]:
    """Generate contextual reasoning and MITRE-style tags."""
    try:
        reasoning = generate_reasoning(
            ai_label=finding.get("ai_label"),
            severity=finding.get("severity"),
            pattern_type=finding.get("pattern_type"),
            source_type=finding.get("source_type"),
            risk_score=finding.get("risk_score"),
            context_window=finding.get("context_window"),
        )
        return {
            "reasoning_summary": reasoning.reasoning_summary,
            "embedding_metadata": reasoning.metadata,
        }
    except Exception as exc:
        LOGGER.exception("Reasoning generation failed: %s", exc)
        return {
            "reasoning_summary": None,
            "embedding_metadata": None,
        }


def enrich_with_explanation(finding: dict[str, Any], classifier_payload: dict[str, Any]) -> dict[str, Any]:
    """Generate SHAP-backed or coefficient-backed explanation data."""
    try:
        explanation = generate_explanation(
            context_window=finding.get("context_window"),
            pattern_type=finding.get("pattern_type"),
            matched_value=finding.get("matched_value"),
        )
        classifier_metadata = dict(classifier_payload.get("classifier_metadata") or {})
        classifier_metadata.update(
            {
                "top_terms": explanation.top_terms,
                "feature_importance": explanation.feature_importance,
                "explanation_source": explanation.source,
            }
        )
        return {
            "shap_explanation": explanation.summary,
            "classifier_metadata": classifier_metadata,
        }
    except Exception as exc:
        LOGGER.exception("Explainability generation failed: %s", exc)
        return {
            "shap_explanation": None,
            "classifier_metadata": classifier_payload.get("classifier_metadata"),
        }


def apply_ai_risk_adjustment(payload: dict[str, Any], ai_payload: dict[str, Any]) -> dict[str, Any]:
    """Boost the score for high-confidence malicious AI labels."""
    risk_score = int(payload.get("risk_score") or 0)
    label = str(ai_payload.get("ai_label") or "")
    confidence = float(ai_payload.get("ai_confidence") or 0.0)

    if label in CRITICAL_AI_LABELS and confidence >= 0.8:
        boost = int(round(confidence * 15))
        risk_score = min(100, risk_score + boost)
        if risk_score >= 90:
            payload["severity"] = "CRITICAL"
        elif risk_score >= 70:
            payload["severity"] = "HIGH"
        payload["risk_score"] = risk_score

    return payload


def derive_source_type(raw_page: dict[str, Any]) -> str:
    """Derive a rough source label from the raw page metadata."""
    url = str(raw_page.get("url") or "").lower()
    if "github" in url:
        return "github"
    if "gitlab" in url:
        return "gitlab"
    if "paste" in url:
        return "paste"
    return "web"


def update_existing_finding_score(finding_id: str, payload: dict[str, Any]) -> bool:
    """Backfill risk score fields for an existing finding row."""
    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client unavailable while updating an existing finding.")
        return False

    try:
        client.table(FINDINGS_TABLE).update(payload).eq("id", finding_id).execute()
        LOGGER.info("[SUCCESS] Updated existing finding with calculated risk score")
        return True
    except Exception as exc:
        LOGGER.exception("Failed to update existing finding %s: %s", finding_id, exc)
        print(f"[WARNING] Failed to update existing finding {finding_id}: {exc}")
        return False


def insert_findings_batch(records: list[dict[str, Any]]) -> int:
    """Insert a batch of findings into Supabase."""
    if not records:
        return 0

    client = get_supabase()
    if client is None:
        LOGGER.error("Supabase client unavailable while inserting findings.")
        print("[ERROR] Could not initialize Supabase client for findings insert")
        return 0

    try:
        client.table(FINDINGS_TABLE).insert(records).execute()
        LOGGER.info("Inserted %s finding record(s) successfully.", len(records))
        return len(records)
    except Exception as exc:
        LOGGER.exception("Failed to insert findings batch: %s", exc)
        print(f"[ERROR] Failed to insert findings batch: {exc}")
        return 0


def _chunked(records: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    """Split records into fixed-size batches."""
    return [records[index : index + size] for index in range(0, len(records), size)]


def main() -> None:
    """Process raw_pages into findings."""
    print("====================================")
    print("DARKSHIELD FINDINGS PROCESSOR")
    print("====================================")
    print(f"[INFO] Started at {datetime.now(timezone.utc).isoformat()}")

    pages = fetch_raw_pages()
    if not pages:
        print("[WARNING] No raw pages found to process")
        return
    target_domains = fetch_target_domains()

    pages_processed = 0
    findings_extracted = 0
    findings_inserted = 0
    skipped_duplicates = 0
    findings_updated = 0
    pending_records: list[dict[str, Any]] = []

    try:
        for raw_page in pages:
            raw_page_id = str(raw_page.get("id", ""))
            raw_text = raw_page.get("raw_text", "")
            fetched_at = raw_page.get("fetched_at")

            if not raw_page_id:
                LOGGER.warning("Skipping raw page without an id.")
                print("[WARNING] Skipping raw page without an id")
                continue

            findings = analyze_text(raw_text)
            pattern_count = len(findings)
            hours_since_found = calculate_hours_since_found(fetched_at)
            pages_processed += 1
            findings_extracted += len(findings)

            for finding in findings:
                target_domain_match = calculate_target_domain_match(raw_page, finding, target_domains)
                scoring_payload = build_finding_record(
                    raw_page=raw_page,
                    finding=finding,
                    pattern_count=pattern_count,
                    target_domain_match=target_domain_match,
                    hours_since_found=hours_since_found,
                )
                ai_payload = enrich_with_ai(finding)
                scoring_payload.update(ai_payload)
                scoring_payload = apply_ai_risk_adjustment(scoring_payload, ai_payload)
                source_type = derive_source_type(raw_page)
                summary_payload = enrich_with_threat_summary(
                    {
                        **finding,
                        "severity": scoring_payload["severity"],
                    },
                    scoring_payload["risk_score"],
                )
                scoring_payload.update(summary_payload)
                classifier_metadata = dict(scoring_payload.get("classifier_metadata") or {})
                classifier_metadata["source_type"] = source_type
                scoring_payload["classifier_metadata"] = classifier_metadata
                reasoning_payload = enrich_with_reasoning(scoring_payload)
                scoring_payload.update(reasoning_payload)
                scoring_payload.update(enrich_with_explanation(scoring_payload, scoring_payload))
                embedding_metadata = build_embedding_metadata(
                    context_window=finding.get("context_window"),
                    pattern_type=finding.get("pattern_type"),
                    matched_value=finding.get("matched_value"),
                    summary=scoring_payload.get("groq_summary"),
                )
                if isinstance(reasoning_payload.get("embedding_metadata"), dict):
                    embedding_metadata.update(reasoning_payload["embedding_metadata"])
                scoring_payload["embedding_metadata"] = embedding_metadata

                existing_finding = finding_exists(raw_page_id, finding["pattern_type"], finding["matched_value"])
                if existing_finding:
                    skipped_duplicates += 1
                    if existing_finding.get("risk_score") in (None, ""):
                        update_payload = {
                            "risk_score": scoring_payload["risk_score"],
                            "severity": scoring_payload["severity"],
                            "target_domain_match": scoring_payload["target_domain_match"],
                            "ai_label": scoring_payload.get("ai_label"),
                            "ai_confidence": scoring_payload.get("ai_confidence"),
                            "groq_summary": scoring_payload.get("groq_summary"),
                            "shap_explanation": scoring_payload.get("shap_explanation"),
                            "reasoning_summary": scoring_payload.get("reasoning_summary"),
                            "embedding_metadata": scoring_payload.get("embedding_metadata"),
                            "classifier_metadata": scoring_payload.get("classifier_metadata"),
                        }
                        if update_existing_finding_score(str(existing_finding["id"]), update_payload):
                            findings_updated += 1
                    continue
                pending_records.append(scoring_payload)

            while len(pending_records) >= BATCH_SIZE:
                batch = pending_records[:BATCH_SIZE]
                inserted = insert_findings_batch(batch)
                findings_inserted += inserted
                if inserted != len(batch):
                    print("[ERROR] Stopping after partial batch insert failure")
                    pending_records = pending_records[BATCH_SIZE:]
                    raise RuntimeError("Findings batch insert failed.")
                alert_service.record_finding_alerts(batch)
                pending_records = pending_records[BATCH_SIZE:]

            print(
                f"[INFO] Pages processed: {pages_processed} | "
                f"Findings extracted: {findings_extracted} | "
                f"Findings inserted: {findings_inserted} | "
                f"Findings updated: {findings_updated} | "
                f"Skipped duplicates: {skipped_duplicates}"
            )

        for batch in _chunked(pending_records, BATCH_SIZE):
            inserted = insert_findings_batch(batch)
            findings_inserted += inserted
            if inserted != len(batch):
                print("[ERROR] Stopping after final batch insert failure")
                raise RuntimeError("Final findings batch insert failed.")
            alert_service.record_finding_alerts(batch)

        print(f"[SUCCESS] Pages processed: {pages_processed}")
        print(f"[SUCCESS] Findings extracted: {findings_extracted}")
        print(f"[SUCCESS] Findings inserted: {findings_inserted}")
        print(f"[SUCCESS] Findings updated: {findings_updated}")
        print(f"[SUCCESS] Skipped duplicates: {skipped_duplicates}")
    except Exception as exc:
        LOGGER.exception("Unexpected error while processing findings: %s", exc)
        print(f"[ERROR] Unexpected error while processing findings: {exc}")


if __name__ == "__main__":
    main()
