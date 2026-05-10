"""Explainability helpers for DarkShield classifier predictions."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.ai.classifier import generate_synthetic_training_data, get_classifier
from app.ai.device import get_device_name, is_cuda_enabled


LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPLANATIONS_DIR = PROJECT_ROOT / "models" / "explanations"


@dataclass
class ExplanationResult:
    summary: str
    top_terms: list[str]
    feature_importance: list[dict[str, Any]]
    source: str
    metadata: dict[str, Any]


def _build_text(context_window: Any, pattern_type: Any, matched_value: Any) -> str:
    return " | ".join(
        [
            str(context_window or "").strip(),
            str(pattern_type or "").strip(),
            str(matched_value or "").strip(),
        ]
    ).strip()


def _hash_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _save_artifact(payload: dict[str, Any], stem: str) -> Path | None:
    try:
        EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)
        path = EXPLANATIONS_DIR / f"{stem}.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path
    except Exception as exc:  # pragma: no cover - filesystem fallback
        LOGGER.warning("Unable to save explanation artifact: %s", exc)
        return None


def _save_plot(feature_importance: list[dict[str, Any]], stem: str) -> Path | None:
    if not feature_importance:
        return None

    try:  # pragma: no cover - plotting is a side artifact
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)
        path = EXPLANATIONS_DIR / f"{stem}.png"
        terms = [str(item.get("term", "")) for item in feature_importance[:8]][::-1]
        scores = [float(item.get("score", 0.0)) for item in feature_importance[:8]][::-1]
        fig, ax = plt.subplots(figsize=(8, 3.5))
        ax.barh(terms, scores, color="#7c8aa5")
        ax.set_xlabel("Contribution")
        ax.set_title("DarkShield Feature Contributions")
        fig.tight_layout()
        fig.savefig(path, dpi=160)
        plt.close(fig)
        return path
    except Exception as exc:
        LOGGER.warning("Unable to save explanation plot: %s", exc)
        return None


def _top_terms_from_coefficients(text: str) -> tuple[list[dict[str, Any]], str]:
    classifier = get_classifier()
    pipeline = classifier.pipeline
    if pipeline is None:
        raise RuntimeError("Classifier pipeline is unavailable.")

    vectorizer = pipeline.named_steps["vectorizer"]
    model = pipeline.named_steps["model"]
    features = vectorizer.get_feature_names_out()
    vector = vectorizer.transform([text])
    classes = list(model.classes_)
    predicted = model.predict(vector)[0]
    class_index = classes.index(predicted)
    coefficients = np.asarray(model.coef_[class_index]).ravel()
    values = vector.toarray().ravel()
    contributions = values * coefficients
    ranked_indices = np.argsort(np.abs(contributions))[::-1]
    feature_importance: list[dict[str, Any]] = []
    for index in ranked_indices[:10]:
        score = float(contributions[index])
        if score == 0.0:
            continue
        feature_importance.append(
            {
                "term": str(features[index]),
                "score": score,
            }
        )
    return feature_importance, str(predicted)


def _try_shap_explanation(text: str) -> tuple[list[dict[str, Any]], str] | None:
    try:
        shap_flag = os.getenv("ENABLE_SHAP")
        if shap_flag is None:
            shap_flag = os.getenv("DARKSHIELD_USE_SHAP", "")
        if shap_flag.strip().lower() not in {"1", "true", "yes", "on"}:
            return None

        import shap  # type: ignore

        classifier = get_classifier()
        pipeline = classifier.pipeline
        if pipeline is None:
            return None

        vectorizer = pipeline.named_steps["vectorizer"]
        model = pipeline.named_steps["model"]
        background = vectorizer.transform(
            generate_synthetic_training_data(multiplier=4)["context_window"]
            .astype(str)
            .head(24)
            .tolist()
        )
        sample = vectorizer.transform([text])
        explainer = shap.LinearExplainer(model, background)
        shap_values = explainer.shap_values(sample)
        if isinstance(shap_values, list):
            class_index = int(np.argmax(model.predict_proba(sample)[0]))
            values = shap_values[class_index].toarray().ravel() if hasattr(shap_values[class_index], "toarray") else np.asarray(shap_values[class_index]).ravel()
        else:
            values = np.asarray(shap_values).ravel()

        features = vectorizer.get_feature_names_out()
        ranked_indices = np.argsort(np.abs(values))[::-1]
        feature_importance: list[dict[str, Any]] = []
        for index in ranked_indices[:10]:
            score = float(values[index])
            if score == 0.0:
                continue
            feature_importance.append({"term": str(features[index]), "score": score})
        predicted = str(model.predict(sample)[0])
        return feature_importance, predicted
    except Exception as exc:  # pragma: no cover - optional dependency fallback
        LOGGER.warning("SHAP explanation fallback used: %s", exc)
        return None


def generate_explanation(
    context_window: Any,
    pattern_type: Any,
    matched_value: Any,
) -> ExplanationResult:
    """Generate a sparse-text explanation with SHAP or linear coefficients."""
    text = _build_text(context_window, pattern_type, matched_value)
    text_hash = _hash_text(text)

    try:
        shap_result = _try_shap_explanation(text)
        if shap_result is not None:
            feature_importance, predicted_label = shap_result
            source = "shap"
        else:
            feature_importance, predicted_label = _top_terms_from_coefficients(text)
            source = "coefficients"
    except Exception as exc:
        LOGGER.exception("Explainability generation failed: %s", exc)
        feature_importance, predicted_label = [], "unknown"
        source = "fallback"

    top_terms = [str(item.get("term", "")) for item in feature_importance[:5] if item.get("term")]
    summary = (
        f"Prediction `{predicted_label}` was driven by terms: {', '.join(top_terms)}."
        if top_terms
        else f"Prediction `{predicted_label}` did not surface stable feature contributions."
    )
    metadata = {
        "text_hash": text_hash,
        "predicted_label": predicted_label,
        "source": source,
        "feature_count": len(feature_importance),
        "device": get_device_name(),
        "cuda_enabled": is_cuda_enabled(),
    }

    artifact_payload = {
        "summary": summary,
        "feature_importance": feature_importance,
        "metadata": metadata,
    }
    json_path = _save_artifact(artifact_payload, text_hash)
    plot_path = _save_plot(feature_importance, text_hash)
    if json_path:
        metadata["artifact_path"] = str(json_path)
    if plot_path:
        metadata["plot_path"] = str(plot_path)

    return ExplanationResult(
        summary=summary,
        top_terms=top_terms,
        feature_importance=feature_importance,
        source=source,
        metadata=metadata,
    )
