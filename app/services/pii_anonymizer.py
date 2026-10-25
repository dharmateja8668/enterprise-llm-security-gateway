"""
app/services/pii_anonymizer.py
PII Anonymization and Deanonymization Service (Week 2, Day 4-6).

Provides a secure, reusable service layer for:
1. Detecting and replacing sensitive PII with standardized deterministic placeholders.
2. Preventing placeholder collisions with user-supplied text.
3. Restoring placeholders from LLM responses supporting controlled formatting variants
   while failing closed on malformed, partial, or unknown placeholders.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Set, Tuple

from app.services.pii_analyzer import PIIEntity, analyze_pii

logger = logging.getLogger(__name__)

# Normalize Presidio entity names to concise enterprise standard tokens
NORMALIZE_ENTITY_TYPE: Dict[str, str] = {
    "US_SSN": "SSN",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
}

# Regex pattern to identify pre-existing text that looks like placeholders
EXISTING_PLACEHOLDER_PATTERN = re.compile(
    r"(?:<|\[)?(?:PII_)?([A-Za-z_]+)_(\d+)(?:>|\])?",
    re.IGNORECASE,
)


def _resolve_non_overlapping_entities(entities: List[PIIEntity]) -> List[PIIEntity]:
    """
    Filter out overlapping entity spans, prioritizing higher confidence scores
    and longer spans to avoid text slicing corruption.
    """
    if not entities:
        return []

    # Sort primarily by score desc, secondarily by length desc
    sorted_candidates = sorted(
        entities,
        key=lambda e: (e.score, (e.end - e.start)),
        reverse=True,
    )

    resolved: List[PIIEntity] = []
    for candidate in sorted_candidates:
        # Check if candidate overlaps with any already accepted entity
        overlaps = False
        for accepted in resolved:
            if not (candidate.end <= accepted.start or candidate.start >= accepted.end):
                overlaps = True
                break
        if not overlaps:
            resolved.append(candidate)

    # Sort final entities descending by start position for slice replacement
    resolved.sort(key=lambda e: e.start, reverse=True)
    return resolved


def anonymize(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Anonymize text by replacing detected PII with deterministic, collision-safe placeholders.

    Placeholder format:
        <PII_{ENTITY_TYPE}_{INDEX}>
        e.g., <PII_PERSON_1>, <PII_EMAIL_ADDRESS_1>, <PII_CREDIT_CARD_1>

    Guarantees:
    - Deterministic within a request: identical values get identical placeholders.
    - Unique per distinct entity: different values get distinct indices.
    - Collision-resistant: scans input text for existing tokens resembling placeholders
      and reserves those indices so newly generated placeholders never collide.
    - Preserves all surrounding text, whitespace, Markdown, JSON, and punctuation.
    - Never exposes raw PII in logs.

    Args:
        text: The original text containing sensitive PII.

    Returns:
        A tuple of (anonymized_text, mapping_dict) where mapping_dict
        maps placeholder -> original_value.
    """
    if not text:
        return text, {}

    try:
        entities = analyze_pii(text, score_threshold=0.0)
    except Exception as exc:
        logger.error("PII analysis failed during anonymization: %s", exc)
        raise RuntimeError("PII scanning failed; failing closed for security") from exc

    if not entities:
        return text, {}

    # Scan for existing placeholder-like tokens in user text to prevent collisions
    used_indices: Dict[str, Set[int]] = {}
    for match in EXISTING_PLACEHOLDER_PATTERN.finditer(text):
        raw_type = match.group(1).upper()
        norm_type = NORMALIZE_ENTITY_TYPE.get(raw_type, raw_type)
        idx = int(match.group(2))
        used_indices.setdefault(norm_type, set()).add(idx)

    # Resolve overlaps so text replacements do not corrupt slices
    clean_entities = _resolve_non_overlapping_entities(entities)

    mapping: Dict[str, str] = {}
    reverse_mapping: Dict[str, str] = {}  # original_value -> placeholder
    counters: Dict[str, int] = {}

    anonymized_text = text

    for entity in clean_entities:
        original_value = entity.text_snippet

        # If already encountered this exact string in this request, reuse placeholder
        if original_value in reverse_mapping:
            placeholder = reverse_mapping[original_value]
        else:
            raw_type = entity.entity_type
            entity_type = NORMALIZE_ENTITY_TYPE.get(raw_type, raw_type)

            # Find the next available index not pre-existing in user text
            current_idx = counters.get(entity_type, 0) + 1
            existing_for_type = used_indices.setdefault(entity_type, set())
            while current_idx in existing_for_type:
                current_idx += 1

            counters[entity_type] = current_idx
            existing_for_type.add(current_idx)

            placeholder = f"<PII_{entity_type}_{current_idx}>"
            mapping[placeholder] = original_value
            reverse_mapping[original_value] = placeholder

        # Splice placeholder into text at original entity coordinates
        anonymized_text = (
            anonymized_text[: entity.start]
            + placeholder
            + anonymized_text[entity.end :]
        )

    logger.info("PII anonymization completed: %d entities replaced.", len(mapping))
    return anonymized_text, mapping


def deanonymize(text: str, mapping: Dict[str, str]) -> str:
    """
    Restore original values in a text containing placeholders returned by an LLM.

    Supported placeholder formats:
    - Standard angle brackets: <PII_PERSON_1>, < PII_PERSON_1 >
    - Square brackets: [PII_PERSON_1], [ PII_PERSON_1 ]
    - Standalone bare tokens: PII_PERSON_1 (with word/bracket boundaries)
    - Legacy placeholders: <PERSON_1>, [PERSON_1], PERSON_1 (if present in mapping)

    Security Principles (Fail-Closed):
    - Only restores tokens present in this request's mapping.
    - If the LLM omits placeholders, returns text as-is (does not guess or hallucinate).
    - If placeholders are malformed or unbalanced (e.g. `<PII_PERSON_1` or `PII_PERSON_1>`),
      they are left untouched.
    - Never uses broad substring replace to avoid corrupting ordinary text.
    - Never logs mapping or restored PII.

    Args:
        text: The text (e.g., LLM response) containing placeholders.
        mapping: The dictionary mapping placeholder -> original value.

    Returns:
        The text with safely matched placeholders replaced by their original values.
    """
    if not text or not mapping:
        return text

    deanonymized_text = text

    # Sort placeholders by core token length descending to prevent shorter tokens
    # (e.g., PII_PERSON_1) from interfering with longer ones (e.g., PII_PERSON_10)
    sorted_items = sorted(
        mapping.items(),
        key=lambda item: len(item[0].strip("<>[]")),
        reverse=True,
    )

    restored_count = 0

    for placeholder, original_value in sorted_items:
        core = placeholder.strip("<>[]").strip()
        if not core:
            continue

        escaped_core = re.escape(core)

        # Regex components:
        # 1. Balanced angle brackets: <\s*CORE\s*>
        # 2. Balanced square brackets: \[\s*CORE\s*\]
        # 3. Standalone bare token: (?<![<\[\w])CORE(?![>\]\w])
        # Unbalanced brackets like `<CORE` or `CORE>` are excluded and fail closed.
        pattern = (
            r"(?:"
            + r"<\s*" + escaped_core + r"\s*>"
            + r"|"
            + r"\[\s*" + escaped_core + r"\s*\]"
            + r"|"
            + r"(?<![<\[\w])" + escaped_core + r"(?![>\]\w])"
            + r")"
        )

        new_text, count = re.subn(
            pattern,
            lambda _m: original_value,
            deanonymized_text,
            flags=re.IGNORECASE,
        )
        deanonymized_text = new_text
        restored_count += count

    logger.info("PII deanonymization completed: %d placeholders restored.", restored_count)
    return deanonymized_text
