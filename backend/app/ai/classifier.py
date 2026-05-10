"""Lightweight cybersecurity text classifier for DarkShield."""

from __future__ import annotations

import json
import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODELS_DIR / "darkshield_ai_classifier.joblib"
LOGGER = logging.getLogger(__name__)

LABELS = [
    "credential_leak",
    "api_key_exposure",
    "infrastructure_exposure",
    "suspicious_activity",
    "benign",
]


def _normalize_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"https?://\S+", " url ", text)
    text = re.sub(r"\b[\w.-]+@[\w.-]+\.\w+\b", " email ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _build_text(context_window: Any, pattern_type: Any, matched_value: Any) -> str:
    return " | ".join(
        [
            _normalize_text(context_window),
            f"pattern_type {_normalize_text(pattern_type)}",
            f"matched_value {_normalize_text(matched_value)}",
        ]
    ).strip()


def _synthetic_templates() -> dict[str, list[tuple[str, str, str]]]:
    return {
        "credential_leak": [
            ("password reset token exposed in plain text", "email", "user@example.com"),
            ("user password and session token shared in logs", "password", "hunter2"),
            ("plaintext credentials visible in config file", "secret", "db_password"),
        ],
        "api_key_exposure": [
            ("api key found in source code and build logs", "api_key", "sk-live-1234"),
            ("github token exposed in repository history", "api_key", "ghp_abcdef"),
            ("service credential looks like a bearer token", "api_key", "Bearer abc"),
        ],
        "infrastructure_exposure": [
            ("production ip address and hostname leaked", "ipv4", "10.0.0.5"),
            ("aws instance metadata endpoint referenced", "hostname", "ec2.internal"),
            ("internal service url present in public artifact", "domain", "internal.company.local"),
        ],
        "suspicious_activity": [
            ("repeated failed login attempts from same host", "behavior", "failed login"),
            ("mass download and enumeration pattern detected", "activity", "enumeration"),
            ("unexpected access pattern from automation script", "behavior", "script"),
        ],
        "benign": [
            ("documentation mentions example placeholder values", "docs", "example"),
            ("sanitized sample data for testing only", "sample", "demo"),
            ("non sensitive status message in a note", "note", "hello world"),
        ],
    }


def generate_synthetic_training_data(multiplier: int = 80) -> pd.DataFrame:
    rows: list[dict[str, str]] = []
    rng = np.random.default_rng(42)
    templates = _synthetic_templates()
    for label, examples in templates.items():
        for index in range(multiplier):
            context_window, pattern_type, matched_value = examples[index % len(examples)]
            filler = rng.choice(
                [
                    "urgent analyst review",
                    "observed during pipeline scan",
                    "detected in workspace feed",
                    "customer facing asset",
                    "internal security log",
                ]
            )
            rows.append(
                {
                    "context_window": f"{context_window} {filler}",
                    "pattern_type": pattern_type,
                    "matched_value": matched_value,
                    "label": label,
                }
            )
    return pd.DataFrame(rows)


@dataclass
class PredictionResult:
    label: str
    confidence: float
    probabilities: dict[str, float]


class CyberThreatClassifier:
    """TF-IDF + logistic regression classifier for DarkShield signals."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = model_path or MODEL_PATH
        self.pipeline: Pipeline | None = None
        self.metadata: dict[str, Any] = {}

    @property
    def is_trained(self) -> bool:
        return self.pipeline is not None

    def _build_pipeline(self) -> Pipeline:
        vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            stop_words="english",
        )
        model = LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            multi_class="auto",
        )
        return Pipeline(
            steps=[
                ("vectorizer", vectorizer),
                ("model", model),
            ]
        )

    def train_model(self, training_data: pd.DataFrame | None = None) -> dict[str, Any]:
        data = training_data.copy() if training_data is not None else generate_synthetic_training_data()
        if data.empty:
            raise ValueError("Training data is empty.")

        data = data.fillna("")
        data["text"] = data.apply(
            lambda row: _build_text(row.get("context_window"), row.get("pattern_type"), row.get("matched_value")),
            axis=1,
        )
        X_train, X_test, y_train, y_test = train_test_split(
            data["text"],
            data["label"],
            test_size=0.2,
            random_state=42,
            stratify=data["label"],
        )

        pipeline = self._build_pipeline()
        pipeline.fit(X_train, y_train)
        predictions = pipeline.predict(X_test)

        report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
        matrix = confusion_matrix(y_test, predictions, labels=LABELS)

        self.pipeline = pipeline
        self.metadata = {
            "labels": LABELS,
            "training_rows": len(data),
            "class_distribution": Counter(data["label"]),
            "classification_report": report,
            "confusion_matrix": matrix.tolist(),
        }

        LOGGER.info("AI classifier trained on %s synthetic rows.", len(data))
        LOGGER.info("Classification report:\n%s", json.dumps(report, indent=2))
        LOGGER.info("Confusion matrix: %s", matrix.tolist())
        return self.metadata

    def save_model(self) -> Path:
        if self.pipeline is None:
            raise RuntimeError("Classifier is not trained.")

        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "pipeline": self.pipeline,
            "metadata": self.metadata,
        }
        joblib.dump(payload, self.model_path)
        LOGGER.info("Saved AI classifier to %s", self.model_path)
        return self.model_path

    def load_model(self) -> "CyberThreatClassifier":
        if self.model_path.exists():
            payload = joblib.load(self.model_path)
            self.pipeline = payload.get("pipeline")
            self.metadata = payload.get("metadata", {})
            LOGGER.info("Loaded AI classifier from %s", self.model_path)
            return self

        self.train_model()
        self.save_model()
        return self

    def predict(self, context_window: Any, pattern_type: Any, matched_value: Any) -> PredictionResult:
        if self.pipeline is None:
            self.load_model()

        assert self.pipeline is not None
        text = _build_text(context_window, pattern_type, matched_value)
        probabilities = self.pipeline.predict_proba([text])[0]
        classes = list(self.pipeline.classes_)
        probability_map = {str(label): float(prob) for label, prob in zip(classes, probabilities)}
        label = max(probability_map, key=probability_map.get)
        confidence = float(probability_map[label])
        return PredictionResult(label=label, confidence=confidence, probabilities=probability_map)

    def predict_label(self, context_window: Any, pattern_type: Any, matched_value: Any) -> str:
        return self.predict(context_window, pattern_type, matched_value).label

    def predict_confidence(self, context_window: Any, pattern_type: Any, matched_value: Any) -> float:
        return self.predict(context_window, pattern_type, matched_value).confidence


@lru_cache(maxsize=1)
def get_classifier() -> CyberThreatClassifier:
    classifier = CyberThreatClassifier()
    return classifier.load_model()


def train_model() -> dict[str, Any]:
    classifier = CyberThreatClassifier()
    metadata = classifier.train_model()
    classifier.save_model()
    return metadata


def predict_label(context_window: Any, pattern_type: Any, matched_value: Any) -> str:
    return get_classifier().predict_label(context_window, pattern_type, matched_value)


def predict_confidence(context_window: Any, pattern_type: Any, matched_value: Any) -> float:
    return get_classifier().predict_confidence(context_window, pattern_type, matched_value)


def save_model() -> Path:
    classifier = get_classifier()
    return classifier.save_model()


def load_model() -> CyberThreatClassifier:
    return get_classifier()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    classifier = CyberThreatClassifier()
    metadata = classifier.train_model()
    classifier.save_model()
    print(json.dumps(metadata, indent=2, default=str))
    sample = classifier.predict(
        "github token exposed in commit history",
        "api_key",
        "ghp_123456",
    )
    print(json.dumps(sample.__dict__, indent=2, default=str))


if __name__ == "__main__":
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    main()

