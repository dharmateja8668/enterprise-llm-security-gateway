"""
app/services/pii_analyzer.py
PII Detection Service — Microsoft Presidio Integration (Week 2, Day 1).

Provides a reusable service layer for detecting Personally Identifiable
Information (PII) in text using the Presidio AnalyzerEngine.

Day 1 scope: **Detection only** — no anonymization or redaction.

The module is designed to be extensible:
  - Custom recognizers (e.g., internal project codes) can be registered
    via ``register_custom_recognizer()`` in Day 2/3.
  - The analyzer engine is lazily initialized as a module-level singleton
    to avoid repeated startup cost.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from typing import List, Optional, Sequence

from presidio_analyzer import AnalyzerEngine, RecognizerResult, EntityRecognizer, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII result data class
# ---------------------------------------------------------------------------

@dataclass
class PIIEntity:
    """Structured representation of a single detected PII entity."""

    entity_type: str
    start: int
    end: int
    score: float
    text_snippet: str  # the matched substring (for audit/debug; never log in prod)

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary (useful for JSON responses)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Default entity types to scan for
# ---------------------------------------------------------------------------

DEFAULT_ENTITIES: List[str] = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "INTERNAL_PROJECT_CODE",
]

# ---------------------------------------------------------------------------
from presidio_analyzer.predefined_recognizers import UsSsnRecognizer

import re

class RelaxedUsSsnRecognizer(UsSsnRecognizer):
    """Extends Presidio's UsSsnRecognizer to ensure formatted synthetic/sample SSNs
    (e.g., 123-45-6789) are protected and not discarded as non-PII example numbers."""

    def invalidate_result(self, pattern_text: str) -> bool:
        only_digits = "".join(c for c in pattern_text if c.isdigit())
        # If formatted with delimiters (e.g., 123-45-6789), treat as sensitive PII
        if any(c in pattern_text for c in "-. ") and only_digits in ("123456789", "987654320", "078051120"):
            return False
        return super().invalidate_result(pattern_text)


class ContextPersonRecognizer(EntityRecognizer):
    """Recognizes person names following contextual phrases (e.g., 'my name is X', 'I am X')."""

    def __init__(self):
        super().__init__(
            supported_entities=["PERSON"],
            name="ContextPersonRecognizer"
        )
        self.pattern = re.compile(
            r"(?i)\b(?:my name is|name is|i am|this is|call me|name:?)\s+([A-Za-z]{2,30})\b"
        )

    def load(self) -> None:
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        results = []
        if "PERSON" not in entities and entities != []:
            # If specific entities were requested and PERSON is not among them, skip
            if "PERSON" not in entities:
                return results
        for match in self.pattern.finditer(text):
            results.append(
                RecognizerResult(
                    entity_type="PERSON",
                    start=match.start(1),
                    end=match.end(1),
                    score=0.85,
                )
            )
        return results


class FormattedCreditCardRecognizer(EntityRecognizer):
    """Recognizes formatted credit card numbers with hyphens/spaces or raw 13-19 digits."""

    def __init__(self):
        super().__init__(
            supported_entities=["CREDIT_CARD"],
            name="FormattedCreditCardRecognizer"
        )
        self.pattern = re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b"
        )

    def load(self) -> None:
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        results = []
        for match in self.pattern.finditer(text):
            results.append(
                RecognizerResult(
                    entity_type="CREDIT_CARD",
                    start=match.start(),
                    end=match.end(),
                    score=0.9,
                )
            )
        return results


_analyzer_engine: Optional[AnalyzerEngine] = None


def _get_analyzer() -> AnalyzerEngine:
    """Return the shared AnalyzerEngine, creating it on first call.

    The engine is created once and cached at module level so that every
    request does not pay the initialization cost.
    """
    global _analyzer_engine
    if _analyzer_engine is None:
        logger.info("Initializing Presidio AnalyzerEngine …")
        
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        nlp_engine = provider.create_engine()
        _analyzer_engine = AnalyzerEngine(nlp_engine=nlp_engine)
        
        # Replace default UsSsnRecognizer with RelaxedUsSsnRecognizer
        try:
            _analyzer_engine.registry.remove_recognizer("UsSsnRecognizer")
        except Exception:
            pass
        _analyzer_engine.registry.add_recognizer(RelaxedUsSsnRecognizer())
        _analyzer_engine.registry.add_recognizer(ContextPersonRecognizer())
        _analyzer_engine.registry.add_recognizer(FormattedCreditCardRecognizer())

        # Register custom recognizer for Internal Project Codes
        # Note: This is a placeholder format (ZAALIMA-PROJ-YYYY-NNN) and can be replaced 
        # with the organization's actual project-code format later.
        project_code_pattern = Pattern(
            name="zaalima_project_code",
            regex=r"ZAALIMA\s*-\s*PROJ\s*-\s*\d{4}\s*-\s*\d{3}",
            score=0.8
        )
        project_code_recognizer = PatternRecognizer(
            supported_entity="INTERNAL_PROJECT_CODE", 
            patterns=[project_code_pattern]
        )
        _analyzer_engine.registry.add_recognizer(project_code_recognizer)
        
        # Add embedded credit card recognizer to catch CCs without word boundaries
        cc_pattern = Pattern(
            name="embedded_cc",
            regex=r"4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}",
            score=0.5
        )
        cc_recognizer = PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[cc_pattern]
        )
        _analyzer_engine.registry.add_recognizer(cc_recognizer)

        logger.info("Presidio AnalyzerEngine ready.")
    return _analyzer_engine


def reset_analyzer() -> None:
    """Reset the cached engine (useful in tests or when adding custom recognizers)."""
    global _analyzer_engine
    _analyzer_engine = None


# ---------------------------------------------------------------------------
# Custom recognizer registration (placeholder for Day 2/3)
# ---------------------------------------------------------------------------

def register_custom_recognizer(recognizer: EntityRecognizer) -> None:
    """Register a custom Presidio recognizer with the shared engine.

    This allows adding organization-specific patterns (e.g., internal
    project codes) without rebuilding the entire engine.

    Args:
        recognizer: A ``presidio_analyzer.EntityRecognizer`` subclass instance.
    """
    engine = _get_analyzer()
    engine.registry.add_recognizer(recognizer)
    logger.info("Registered custom recognizer: %s", type(recognizer).__name__)


# ---------------------------------------------------------------------------
# Core PII analysis function
# ---------------------------------------------------------------------------

def analyze_pii(
    text: str,
    *,
    language: str = "en",
    entities: Optional[Sequence[str]] = None,
    score_threshold: float = 0.0,
) -> List[PIIEntity]:
    """Analyze ``text`` for PII entities using Presidio.

    Args:
        text: The input string to scan (e.g., a user prompt).
        language: ISO-639-1 language code. Defaults to ``"en"``.
        entities: Specific entity types to look for. If ``None``,
            :data:`DEFAULT_ENTITIES` is used.
        score_threshold: Minimum confidence score to include a result.
            Defaults to ``0.0`` (return everything Presidio finds).

    Returns:
        A list of :class:`PIIEntity` objects sorted by start position.

    Note:
        This function performs **detection only**. The original text is
        never modified. Anonymization will be added in Day 2/3.
    """
    engine = _get_analyzer()
    target_entities = list(entities) if entities else DEFAULT_ENTITIES

    results: List[RecognizerResult] = engine.analyze(
        text=text,
        language=language,
        entities=target_entities,
        score_threshold=score_threshold,
    )

    pii_entities: List[PIIEntity] = []
    for r in sorted(results, key=lambda x: x.start):
        pii_entities.append(
            PIIEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=round(r.score, 4),
                text_snippet=text[r.start : r.end],
            )
        )

    if pii_entities:
        logger.info(
            "PII scan found %d entit%s in text (%d chars).",
            len(pii_entities),
            "y" if len(pii_entities) == 1 else "ies",
            len(text),
        )
    else:
        logger.debug("PII scan: no entities detected in text (%d chars).", len(text))

    return pii_entities


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def contains_pii(text: str, *, score_threshold: float = 0.5) -> bool:
    """Quick check: does ``text`` contain any PII above the threshold?

    Uses a higher default threshold (0.5) than :func:`analyze_pii` to
    reduce false positives for quick gate checks.
    """
    return len(analyze_pii(text, score_threshold=score_threshold)) > 0


def summarize_pii(entities: List[PIIEntity]) -> dict:
    """Return a concise summary suitable for audit logs or API responses.

    Returns:
        A dict with ``pii_detected`` (bool), ``count`` (int),
        and ``entity_types`` (list of unique type strings).
    """
    unique_types = sorted({e.entity_type for e in entities})
    return {
        "pii_detected": len(entities) > 0,
        "count": len(entities),
        "entity_types": unique_types,
    }
