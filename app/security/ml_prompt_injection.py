"""
app/security/ml_prompt_injection.py
Week 3 - Day 2: Local ML-Based Prompt Injection Detection.

Provides a singleton LocalPromptInjectionDetector that wraps the
pretrained HuggingFace model:

    protectai/deberta-v3-base-prompt-injection-v2

Model details (verified from config.json)
------------------------------------------
Architecture : DebertaV2ForSequenceClassification
Labels       : { 0: "SAFE", 1: "INJECTION" }
Score        : The pipeline returns the score for the predicted label.
               When label == "INJECTION" and score >= threshold BLOCK.
               In all cases the injection_score stored is the raw
               softmax probability assigned to the INJECTION class.

Design decisions
-----------------
* Model and tokenizer are loaded ONCE at detector construction time,
  not per-request.
* CPU is used by default; CUDA/MPS is selected automatically when available.
* If the model fails to load, the detector enters _available = False
  mode and every detect() call returns None so the caller can fall
  back to the heuristic layer -- security is never silently bypassed.
* Inference time is measured and returned so callers can log it.

Configuration (environment variables)
---------------------------------------
ML_PROMPT_INJECTION_ENABLED   - true/false (default: true).
ML_PROMPT_INJECTION_MODEL     - HuggingFace model ID
                                (default: protectai/deberta-v3-base-prompt-injection-v2).
ML_PROMPT_INJECTION_THRESHOLD - Float 0.0-1.0 (default: 0.5).
                                INJECTION score must meet or exceed this
                                value to classify as injection.

Public API
-----------
get_ml_detector() -> LocalPromptInjectionDetector
    Returns the application-level singleton detector.

LocalPromptInjectionDetector.detect(prompt) -> MLDetectionResult | None
    Returns None when the ML detector is unavailable/disabled.

reset_ml_detector()
    Reset the singleton (used by tests).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_INJECTION_LABEL = "INJECTION"
_SAFE_LABEL = "SAFE"


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------

@dataclass
class MLDetectionResult:
    """Result produced by the local ML detector.

    Attributes:
        is_injection:      True when the ML model classifies the prompt as
                           a prompt injection attack.
        injection_score:   Softmax probability assigned to the INJECTION
                           class (always in [0.0, 1.0]).
        label:             Raw label returned by the pipeline
                           ("INJECTION" or "SAFE").
        inference_time_ms: Wall-clock time for the model inference call,
                           in milliseconds.
    """
    is_injection: bool
    injection_score: float
    label: str
    inference_time_ms: float


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _ml_enabled() -> bool:
    """Return True when local ML detection is configured as active."""
    return os.getenv("ML_PROMPT_INJECTION_ENABLED", "true").lower() == "true"


def _ml_model_id() -> str:
    """Return the HuggingFace model ID to use."""
    return os.getenv("ML_PROMPT_INJECTION_MODEL", _DEFAULT_MODEL).strip()


def _ml_threshold() -> float:
    """Return the ML injection-score threshold (default 0.5)."""
    try:
        value = float(os.getenv("ML_PROMPT_INJECTION_THRESHOLD", "0.5"))
        return max(0.0, min(1.0, value))
    except ValueError:
        logger.warning(
            "Invalid ML_PROMPT_INJECTION_THRESHOLD; using default 0.5"
        )
        return 0.5


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class LocalPromptInjectionDetector:
    """Wraps the ProtectAI DeBERTa-v3-base prompt injection classifier.

    The HuggingFace pipeline (text-classification) is constructed once
    during __init__. Subsequent detect() calls reuse the pipeline,
    avoiding repeated model loading.

    Label mapping (from config.json, verified 2026-09-25):
        0 -> SAFE
        1 -> INJECTION

    The pipeline is invoked with top_k=None so we always receive scores
    for BOTH labels. We then extract the INJECTION class probability
    independently of which label "won".
    """

    def __init__(self) -> None:
        self._available: bool = False
        self._pipeline = None
        self._model_id: str = _ml_model_id()

        if not _ml_enabled():
            logger.info(
                "ML prompt injection detection is disabled "
                "(ML_PROMPT_INJECTION_ENABLED=false)."
            )
            return

        self._load_model()

    # ------------------------------------------------------------------
    # Internal model loading
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the tokenizer + model and build the HuggingFace pipeline.

        Sets _available = True on success, False on any error.
        Never raises.
        """
        try:
            import torch  # type: ignore[import]
            from transformers import (  # type: ignore[import]
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )
        except ImportError as exc:
            logger.error(
                "Cannot import torch/transformers: %s - "
                "ML prompt injection detection will be unavailable. "
                "Install with: pip install torch transformers sentencepiece",
                exc,
            )
            return

        try:
            # Determine device: CUDA > MPS (Apple Silicon) > CPU
            if torch.cuda.is_available():
                device = torch.device("cuda")
                device_label = "CUDA"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                device = torch.device("mps")
                device_label = "MPS"
            else:
                device = torch.device("cpu")
                device_label = "CPU"

            logger.info(
                "Loading ML prompt injection model '%s' on %s ...",
                self._model_id,
                device_label,
            )
            load_start = time.time()

            tokenizer = AutoTokenizer.from_pretrained(self._model_id)
            model = AutoModelForSequenceClassification.from_pretrained(
                self._model_id
            )
            model.to(device)
            model.eval()

            # Build the pipeline.
            # top_k=None ensures we get scores for ALL labels, not just
            # the winning label. This lets us reliably extract the
            # INJECTION class probability regardless of the "winner".
            self._pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                truncation=True,
                max_length=512,
                top_k=None,
                device=device,
            )

            load_elapsed = (time.time() - load_start) * 1000
            self._available = True

            logger.info(
                "ML model '%s' loaded successfully on %s (%.0f ms). "
                "Label mapping: 0->SAFE, 1->INJECTION.",
                self._model_id,
                device_label,
                load_elapsed,
            )

        except Exception as exc:
            logger.error(
                "Failed to load ML prompt injection model '%s': %s - "
                "ML detection unavailable; heuristic layer is still active.",
                self._model_id,
                exc,
                exc_info=True,
            )
            self._available = False

    # ------------------------------------------------------------------
    # Public detection API
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """True when the model loaded successfully and is ready."""
        return self._available

    @property
    def model_id(self) -> str:
        """The HuggingFace model identifier used by this detector."""
        return self._model_id

    def detect(self, prompt: str) -> Optional[MLDetectionResult]:
        """Run ML inference on prompt and return a structured result.

        Returns None when:
        * The ML detector is disabled (ML_PROMPT_INJECTION_ENABLED=false).
        * The model failed to load.
        * Any runtime exception occurs during inference.

        The caller must treat None as "no ML result available" and fall back
        to the heuristic verdict. A None return must NEVER bypass the security
        layer -- it only means ML is unavailable.

        Args:
            prompt: The raw or anonymised user prompt text.

        Returns:
            MLDetectionResult or None.
        """
        if not self._available or self._pipeline is None:
            return None

        try:
            threshold = _ml_threshold()

            t0 = time.perf_counter()
            # pipeline with top_k=None returns:
            # [[{"label": "SAFE", "score": 0.xx}, {"label": "INJECTION", "score": 0.xx}]]
            raw_output = self._pipeline(prompt)
            inference_ms = (time.perf_counter() - t0) * 1000

            scores_list = raw_output[0]

            # Build a dict of label -> score for reliable lookup.
            score_map: dict[str, float] = {
                entry["label"]: entry["score"] for entry in scores_list
            }

            injection_score: float = score_map.get(_INJECTION_LABEL, 0.0)
            is_injection: bool = injection_score >= threshold

            # Best label for logging (highest score).
            best_entry = max(scores_list, key=lambda e: e["score"])
            label = best_entry["label"]

            logger.debug(
                "ML inference: label=%s injection_score=%.4f "
                "threshold=%.2f is_injection=%s inference_ms=%.1f",
                label,
                injection_score,
                threshold,
                is_injection,
                inference_ms,
            )

            return MLDetectionResult(
                is_injection=is_injection,
                injection_score=round(injection_score, 4),
                label=label,
                inference_time_ms=round(inference_ms, 1),
            )

        except Exception as exc:
            logger.error(
                "ML inference failed: %s - "
                "returning None so heuristic result is used.",
                exc,
                exc_info=True,
            )
            return None


# ---------------------------------------------------------------------------
# Application-level singleton
# ---------------------------------------------------------------------------

_detector_instance: Optional[LocalPromptInjectionDetector] = None


def get_ml_detector() -> LocalPromptInjectionDetector:
    """Return the shared LocalPromptInjectionDetector, creating it on first call.

    The model is loaded once at application startup (or on first use) and
    reused for every subsequent request -- never loaded per-request.
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = LocalPromptInjectionDetector()
    return _detector_instance


def reset_ml_detector() -> None:
    """Reset the singleton detector (test helper only).

    Allows tests to patch environment variables and reinitialise the
    detector cleanly.
    """
    global _detector_instance
    _detector_instance = None
