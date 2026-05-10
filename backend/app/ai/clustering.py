"""Similarity and embedding helpers for DarkShield findings."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.ai.device import get_device_name, is_cuda_enabled, log_device_status


LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    SentenceTransformer = None  # type: ignore[assignment]


@dataclass
class EmbeddingResult:
    embeddings: list[list[float]]
    source: str
    dimension: int


def _build_text(
    context_window: Any,
    pattern_type: Any,
    matched_value: Any,
    summary: Any = None,
) -> str:
    return " | ".join(
        [
            str(context_window or "").strip(),
            str(pattern_type or "").strip(),
            str(matched_value or "").strip(),
            str(summary or "").strip(),
        ]
    ).strip()


@lru_cache(maxsize=1)
def _get_sentence_model(model_name: str, device_name: str):
    if SentenceTransformer is None:
        return None

    try:
        log_device_status()
        return SentenceTransformer(model_name or "all-MiniLM-L6-v2", device=device_name)
    except Exception as exc:  # pragma: no cover - runtime fallback
        LOGGER.warning("SentenceTransformer unavailable: %s", exc)
        return None


@lru_cache(maxsize=256)
def _encode_texts_cached(
    texts_key: tuple[str, ...],
    model_name: str,
    device_name: str,
) -> tuple[tuple[float, ...], ...]:
    model = _get_sentence_model(model_name, device_name)
    if model is None:
        vectorizer = TfidfVectorizer(max_features=256, stop_words="english")
        matrix = vectorizer.fit_transform(list(texts_key) or [""])
        return tuple(tuple(float(value) for value in row) for row in matrix.toarray())

    batch_size = 32 if is_cuda_enabled() else 16
    vectors = model.encode(
        list(texts_key),
        batch_size=batch_size,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    array = np.asarray(vectors, dtype=float)
    return tuple(tuple(float(value) for value in row) for row in array)


def generate_embeddings(texts: list[str]) -> EmbeddingResult:
    normalized_texts = [str(text or "").strip() for text in texts]
    model_name = os.getenv("DARKSHIELD_EMBEDDING_MODEL", "all-MiniLM-L6-v2").strip() or "all-MiniLM-L6-v2"
    device_name = get_device_name()
    vectors = _encode_texts_cached(tuple(normalized_texts), model_name, device_name)
    dimension = len(vectors[0]) if vectors else 0
    source = "sentence-transformers" if _get_sentence_model(model_name, device_name) is not None else "tfidf"
    return EmbeddingResult(embeddings=[list(row) for row in vectors], source=source, dimension=dimension)


def build_embedding_metadata(
    context_window: Any,
    pattern_type: Any,
    matched_value: Any,
    summary: Any = None,
) -> dict[str, Any]:
    text = _build_text(context_window, pattern_type, matched_value, summary)
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
    vector = generate_embeddings([text])
    metadata = {
        "embedding_source": vector.source,
        "embedding_dimension": vector.dimension,
        "text_digest": digest,
        "token_count": len(text.split()),
        "summary_present": bool(str(summary or "").strip()),
    }
    return metadata


def cluster_findings(texts: list[str], similarity_threshold: float = 0.78) -> list[list[int]]:
    if not texts:
        return []

    embedding_result = generate_embeddings(texts)
    matrix = np.asarray(embedding_result.embeddings, dtype=float)
    if matrix.size == 0:
        return []

    similarities = cosine_similarity(matrix)
    clusters: list[list[int]] = []
    assigned: set[int] = set()

    for index in range(len(texts)):
        if index in assigned:
            continue

        cluster = [index]
        assigned.add(index)
        for candidate in range(index + 1, len(texts)):
            if candidate in assigned:
                continue
            if similarities[index, candidate] >= similarity_threshold:
                cluster.append(candidate)
                assigned.add(candidate)
        clusters.append(cluster)

    return clusters


def serialize_cluster_preview(texts: list[str], similarity_threshold: float = 0.78) -> str:
    clusters = cluster_findings(texts, similarity_threshold=similarity_threshold)
    return json.dumps({"clusters": clusters, "count": len(clusters)}, indent=2)
