"""Centralized device selection for DarkShield AI workloads."""

from __future__ import annotations

import logging
import os
from functools import lru_cache

try:  # pragma: no cover - import availability depends on local install
    import torch
except Exception:  # pragma: no cover - runtime fallback
    torch = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


def _flag_enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _cuda_ready() -> bool:
    if not _flag_enabled("ENABLE_GPU", default=True):
        return False
    if torch is None:
        return False
    try:
        return bool(torch.cuda.is_available())
    except Exception as exc:  # pragma: no cover - defensive fallback
        LOGGER.warning("CUDA availability check failed: %s", exc)
        return False


@lru_cache(maxsize=1)
def get_device():
    """Return the preferred torch device with CPU fallback."""
    if _cuda_ready():
        return torch.device("cuda")
    if torch is not None:
        return torch.device("cpu")
    return "cpu"


@lru_cache(maxsize=1)
def get_device_name() -> str:
    return str(get_device())


@lru_cache(maxsize=1)
def get_gpu_name() -> str | None:
    if not _cuda_ready():
        return None
    try:
        return str(torch.cuda.get_device_name(0))
    except Exception as exc:  # pragma: no cover - defensive fallback
        LOGGER.warning("Unable to read GPU name: %s", exc)
        return None


def is_cuda_enabled() -> bool:
    return _cuda_ready()


def log_device_status() -> None:
    device = get_device_name()
    gpu_name = get_gpu_name() or "N/A"
    LOGGER.info(
        "AI device selected: %s | cuda_enabled=%s | gpu=%s | enable_gpu=%s | enable_shap=%s",
        device,
        is_cuda_enabled(),
        gpu_name,
        _flag_enabled("ENABLE_GPU", default=True),
        _flag_enabled("ENABLE_SHAP", default=False),
    )
