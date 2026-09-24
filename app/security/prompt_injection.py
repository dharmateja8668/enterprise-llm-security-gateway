"""
app/security/prompt_injection.py
Week 3 – Day 1: Prompt Injection Detection Layer.

Provides a reusable service for detecting prompt injection attacks in user
prompts *before* they are forwarded to the downstream LLM.

Detection pipeline
------------------
1. **Normalize** — lowercase, collapse whitespace, strip invisible characters.
2. **Heuristic** — rule-based regex scan against known injection patterns.
3. **Rebuff (optional)** — remote ML-based scan via the Rebuff cloud API.
4. **Combine** — merge results; the highest risk_score wins; threshold applied.

Public API
----------
``check_prompt_injection(prompt: str) -> InjectionCheckResult``
    The single entry point used by the FastAPI route.

Configuration (environment variables)
--------------------------------------
PROMPT_INJECTION_ENABLED    — ``true`` / ``false`` (default: ``true``).
                              Set to ``false`` to bypass detection entirely
                              (dev / CI use only).
PROMPT_INJECTION_THRESHOLD  — Float 0.0–1.0 (default: ``0.7``).
                              Prompts whose risk_score meets or exceeds this
                              value are classified as injections.
REBUFF_ENABLED              — ``true`` / ``false`` (default: ``false``).
                              Requires a valid REBUFF_API_TOKEN.
REBUFF_API_TOKEN            — Secret token for the Rebuff cloud API.
REBUFF_API_URL              — Override the Rebuff API base URL
                              (default: ``https://playground.rebuff.ai``).

Security notes
--------------
* An exception inside any detector **never** silently bypasses the security
  layer — failures are logged and the heuristic result is used as fallback.
* Prompt text is intentionally **not** stored in logs to comply with the
  project's existing DLP design; only metadata (risk score, category, method)
  is recorded.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------

@dataclass
class InjectionCheckResult:
    """Structured result returned by :func:`check_prompt_injection`.

    Attributes:
        is_injection:     ``True`` when the prompt is classified as a prompt
                          injection attempt.
        risk_score:       Confidence value in the range ``[0.0, 1.0]``.
                          ``0.0`` means no suspicion; ``1.0`` means certain
                          injection.
        reason:           Human-readable explanation of why the prompt was
                          flagged (or ``"safe"`` when clean).
        detection_method: Which detector produced the final verdict.
                          One of ``"disabled"``, ``"heuristic"``,
                          ``"rebuff"``, or ``"combined"``.
    """
    is_injection: bool
    risk_score: float
    reason: str
    detection_method: str


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _detection_enabled() -> bool:
    """Return ``True`` when prompt injection detection is active."""
    return os.getenv("PROMPT_INJECTION_ENABLED", "true").lower() == "true"


def _injection_threshold() -> float:
    """Return the configured risk-score threshold (default ``0.7``)."""
    try:
        value = float(os.getenv("PROMPT_INJECTION_THRESHOLD", "0.7"))
        return max(0.0, min(1.0, value))   # clamp to [0.0, 1.0]
    except ValueError:
        logger.warning(
            "Invalid PROMPT_INJECTION_THRESHOLD value; using default 0.7"
        )
        return 0.7


def _rebuff_enabled() -> bool:
    """Return ``True`` when Rebuff ML detection is configured and active."""
    return (
        os.getenv("REBUFF_ENABLED", "false").lower() == "true"
        and bool(os.getenv("REBUFF_API_TOKEN", "").strip())
    )


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def _normalize(prompt: str) -> str:
    """Return a normalised copy of *prompt* suitable for pattern matching.

    Steps applied
    ~~~~~~~~~~~~~
    1. Unicode NFC normalisation (resolve composed/decomposed characters).
    2. Strip Unicode control characters and invisible code-points.
    3. Lowercase.
    4. Collapse runs of whitespace (spaces, tabs, newlines) to a single space.
    5. Strip leading/trailing whitespace.

    The original prompt is *not* mutated.
    """
    # NFC normalise so that visually identical characters compare equal.
    text = unicodedata.normalize("NFC", prompt)

    # Strip invisible / zero-width characters (category "C" = control/format).
    text = "".join(
        ch for ch in text
        if not unicodedata.category(ch).startswith("C")
        or ch in ("\n", "\r", "\t")  # keep basic whitespace for splitting
    )

    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# Heuristic detection — maintainable pattern list
# ---------------------------------------------------------------------------

# Each entry is (category_label, compiled_regex).
# Patterns are checked against the *normalised* prompt.
# Keep entries narrow enough to avoid false-positives on legitimate prompts.
_HEURISTIC_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # ── Override / ignore instructions ──────────────────────────────────────
    (
        "override_instructions",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|earlier|above|your)\s+"
            r"(instructions?|prompts?|directives?|constraints?|rules?|guidelines?)",
            re.IGNORECASE,
        ),
    ),
    (
        "override_instructions",
        re.compile(
            r"disregard\s+(all\s+)?(previous|prior|earlier|above|your|the)?\s*"
            r"(instructions?|prompts?|directives?|constraints?|rules?|guidelines?)",
            re.IGNORECASE,
        ),
    ),
    (
        "override_instructions",
        re.compile(
            r"forget\s+(all\s+)?(previous|prior|earlier|above|your)?\s*"
            r"(instructions?|prompts?|directives?|constraints?)",
            re.IGNORECASE,
        ),
    ),
    (
        "override_instructions",
        re.compile(
            r"(override|overwrite|replace|supersede)\s+(your\s+)?"
            r"(instructions?|directives?|system\s+prompts?|programming)",
            re.IGNORECASE,
        ),
    ),
    # ── Reveal / exfiltrate system context ──────────────────────────────────
    (
        "reveal_system_prompt",
        re.compile(
            # Matches: "show me your system prompt", "reveal your system instructions",
            # "print your hidden system prompt", "what is your system prompt", etc.
            # The [\w\s]* gap between verb and noun handles intervening words like
            # "me", "your", "the", "hidden", "initial", etc.
            r"(reveal|show|print|output|display|repeat|tell\s+me|give\s+me|"
            r"what\s+is|what\s+are|what\s+were?)\b[\w\s]{0,20}"
            r"(system\s+prompts?|system\s+instructions?|hidden\s+instructions?|"
            r"initial\s+prompts?|base\s+prompts?|original\s+prompts?)",
            re.IGNORECASE,
        ),
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"(what\s+were?\s+you\s+told|what\s+are\s+your\s+(instructions?|rules?|directives?|guidelines?))",
            re.IGNORECASE,
        ),
    ),
    # ── Bypass / jailbreak ──────────────────────────────────────────────────
    (
        "bypass_restrictions",
        re.compile(
            r"bypass\s+(your\s+)?(restrictions?|limitations?|filters?|safeguards?|rules?|policies?)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_restrictions",
        re.compile(
            r"(disable|remove|turn\s+off|circumvent|get\s+around)\s+"
            r"(your\s+)?(restrictions?|limitations?|filters?|safeguards?|content\s+policy|guidelines?)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_restrictions",
        re.compile(
            r"act\s+(as|like)\s+(if|though)?\s*(you\s+(have\s+no|don.t\s+have)\s+(restrictions?|rules?)|"
            r"you\s+(are|were)\s+(unrestricted|jailbroken|uncensored|free))",
            re.IGNORECASE,
        ),
    ),
    # ── Role/persona hijacking ───────────────────────────────────────────────
    (
        "role_hijack",
        re.compile(
            r"(you\s+are\s+now|pretend\s+you\s+are|act\s+as|roleplay\s+as)\s+"
            r".*(without\s+(restrictions?|rules?|ethical|safety|guidelines?)|"
            r"uncensored|jailbroken|unrestricted|no\s+rules?|free\s+to\s+say)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_hijack",
        re.compile(
            r"(your\s+new\s+(instructions?|rules?|directive|programming)\s+(is|are)|"
            r"from\s+now\s+on\s+you\s+(will|must|should|are\s+to))",
            re.IGNORECASE,
        ),
    ),
    # ── DAN / jailbreak keywords ─────────────────────────────────────────────
    (
        "jailbreak_keyword",
        re.compile(
            r"\bdan\b.*(mode|prompt|jailbreak)",
            re.IGNORECASE,
        ),
    ),
    (
        "jailbreak_keyword",
        re.compile(
            r"(jailbreak|developer\s+mode|god\s+mode|unrestricted\s+mode)",
            re.IGNORECASE,
        ),
    ),
    # ── Prompt delimiter / injection separators ──────────────────────────────
    (
        "prompt_delimiter_injection",
        re.compile(
            r"(-{4,}|={4,}|#{4,}|\[system\]|\[inst\]|<\|system\|>|<\|user\|>)\s*"
            r"(ignore|forget|disregard|you\s+are|act\s+as)",
            re.IGNORECASE,
        ),
    ),
]


def _check_heuristic(normalized_prompt: str) -> InjectionCheckResult:
    """Apply rule-based heuristics against *normalized_prompt*.

    Each matching pattern contributes to the risk score.  A single strong
    match returns a score of ``1.0``; the function short-circuits on the
    first match to avoid redundant work.

    Returns a :class:`InjectionCheckResult` — never raises.
    """
    for category, pattern in _HEURISTIC_PATTERNS:
        if pattern.search(normalized_prompt):
            logger.debug(
                "Heuristic match: category=%s pattern=%s",
                category,
                pattern.pattern[:60],
            )
            return InjectionCheckResult(
                is_injection=True,
                risk_score=1.0,
                reason=category,
                detection_method="heuristic",
            )

    return InjectionCheckResult(
        is_injection=False,
        risk_score=0.0,
        reason="safe",
        detection_method="heuristic",
    )


# ---------------------------------------------------------------------------
# Rebuff ML detection adapter
# ---------------------------------------------------------------------------

# Module-level lazy singleton — avoids re-initialisation on every request.
_rebuff_client = None


def _get_rebuff_client():
    """Return the shared Rebuff client, creating it on first call.

    Returns ``None`` if Rebuff is disabled or the token is missing.
    Never raises — failures are logged and ``None`` is returned.
    """
    global _rebuff_client
    if _rebuff_client is not None:
        return _rebuff_client

    if not _rebuff_enabled():
        return None

    api_token = os.getenv("REBUFF_API_TOKEN", "").strip()
    api_url = os.getenv("REBUFF_API_URL", "https://playground.rebuff.ai").strip()

    try:
        from rebuff import Rebuff  # type: ignore[import]
        _rebuff_client = Rebuff(api_token=api_token, api_url=api_url)
        logger.info("Rebuff client initialised (api_url=%s).", api_url)
        return _rebuff_client
    except Exception as exc:
        logger.error(
            "Failed to initialise Rebuff client: %s — "
            "ML detection will be skipped; heuristic detection remains active.",
            exc,
        )
        return None


def _reset_rebuff_client() -> None:
    """Reset the cached Rebuff client (used by tests to inject env changes)."""
    global _rebuff_client
    _rebuff_client = None


def _check_rebuff(prompt: str) -> Optional[InjectionCheckResult]:
    """Call the Rebuff remote API and return a structured result.

    Returns ``None`` in any of the following situations:
    * Rebuff is disabled (``REBUFF_ENABLED != true``).
    * ``REBUFF_API_TOKEN`` is not set.
    * The Rebuff client cannot be initialised.
    * The remote API call fails for any reason.

    The caller must treat ``None`` as "no Rebuff result available" and fall
    back to the heuristic result.  **An exception here must never bypass the
    security layer** — failures are contained and logged.
    """
    client = _get_rebuff_client()
    if client is None:
        return None

    try:
        response = client.detect_injection(user_input=prompt)

        # ``injectionDetected`` is a bool set by the Rebuff SDK.
        is_injection: bool = getattr(response, "injectionDetected", False)

        # Use the highest sub-score as the composite risk score.
        heuristic_score: float = getattr(response, "heuristicScore", 0.0)
        model_score: float = getattr(response, "modelScore", 0.0)
        vector_score_map = getattr(response, "vectorScore", {})
        vector_score: float = (
            vector_score_map.get("topScore", 0.0)
            if isinstance(vector_score_map, dict)
            else 0.0
        )
        risk_score = max(heuristic_score, model_score, vector_score)

        reason = "rebuff_ml_detected" if is_injection else "safe"

        logger.debug(
            "Rebuff result: injection=%s risk_score=%.3f "
            "(heuristic=%.3f model=%.3f vector=%.3f)",
            is_injection,
            risk_score,
            heuristic_score,
            model_score,
            vector_score,
        )

        return InjectionCheckResult(
            is_injection=is_injection,
            risk_score=round(risk_score, 4),
            reason=reason,
            detection_method="rebuff",
        )

    except Exception as exc:
        logger.error(
            "Rebuff detection call failed: %s — "
            "falling back to heuristic result for this request.",
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Combined detection — public entry point
# ---------------------------------------------------------------------------

def check_prompt_injection(prompt: str) -> InjectionCheckResult:
    """Check *prompt* for prompt injection attempts.

    This is the **single public function** that the FastAPI route calls.

    Detection flow
    ~~~~~~~~~~~~~~
    1. If ``PROMPT_INJECTION_ENABLED=false`` -> return SAFE immediately.
    2. Normalise the prompt text.
    3. Run heuristic detection.
    4. If Rebuff is enabled, run Rebuff ML detection.
    5. Combine: the result with the **higher risk_score** is preferred.
    6. Apply the configured threshold; set ``is_injection`` accordingly.

    Design invariant
    ~~~~~~~~~~~~~~~~
    This function **never raises**.  Any internal exception is caught, logged,
    and a safe fallback result is returned.  The caller must not assume that a
    clean return value means "no exception occurred".

    Args:
        prompt: The raw (or anonymised) user prompt to evaluate.

    Returns:
        An :class:`InjectionCheckResult` describing the verdict.
    """
    # -- Guard: detection disabled -------------------------------------------
    if not _detection_enabled():
        return InjectionCheckResult(
            is_injection=False,
            risk_score=0.0,
            reason="detection_disabled",
            detection_method="disabled",
        )

    try:
        threshold = _injection_threshold()
        normalized = _normalize(prompt)

        # -- Step 1: Heuristic -----------------------------------------------
        heuristic_result = _check_heuristic(normalized)

        # Short-circuit: if heuristic already detected injection with certainty
        # (score == 1.0), skip the Rebuff call to save latency.
        if heuristic_result.is_injection and heuristic_result.risk_score >= 1.0:
            logger.debug(
                "Heuristic short-circuit: category=%s", heuristic_result.reason
            )
            return heuristic_result

        # -- Step 2: Rebuff ML (optional) ------------------------------------
        rebuff_result = _check_rebuff(prompt)

        # -- Step 3: Combine -------------------------------------------------
        if rebuff_result is not None:
            # Pick the result with the higher risk score.
            if rebuff_result.risk_score >= heuristic_result.risk_score:
                combined = InjectionCheckResult(
                    is_injection=rebuff_result.risk_score >= threshold,
                    risk_score=rebuff_result.risk_score,
                    reason=rebuff_result.reason,
                    detection_method=(
                        "combined"
                        if heuristic_result.risk_score > 0
                        else "rebuff"
                    ),
                )
            else:
                # Heuristic scored higher but did not hit 1.0 — apply threshold.
                combined = InjectionCheckResult(
                    is_injection=heuristic_result.risk_score >= threshold,
                    risk_score=heuristic_result.risk_score,
                    reason=heuristic_result.reason,
                    detection_method="heuristic",
                )
        else:
            # Rebuff unavailable — apply threshold to heuristic score.
            combined = InjectionCheckResult(
                is_injection=heuristic_result.risk_score >= threshold,
                risk_score=heuristic_result.risk_score,
                reason=heuristic_result.reason,
                detection_method=heuristic_result.detection_method,
            )

        return combined

    except Exception as exc:
        # Last-resort catch: log but do NOT bypass security.
        # Return a blocked result so an unexpected bug cannot open the gate.
        logger.critical(
            "Unexpected error in prompt injection detection: %s — "
            "blocking request as a safety precaution.",
            exc,
            exc_info=True,
        )
        return InjectionCheckResult(
            is_injection=True,
            risk_score=1.0,
            reason="internal_error_fail_closed",
            detection_method="heuristic",
        )
