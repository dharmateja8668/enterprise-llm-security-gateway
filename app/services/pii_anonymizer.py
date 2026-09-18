"""
app/services/pii_anonymizer.py
PII Anonymization and Deanonymization Service (Week 2, Day 4-6).

Provides a reusable service layer for replacing PII in text with placeholders
and restoring those placeholders from LLM responses.
"""

from typing import Tuple, Dict
from app.services.pii_analyzer import analyze_pii


def anonymize(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Anonymize text by replacing detected PII with unique placeholders.

    Args:
        text: The original text containing PII.

    Returns:
        A tuple of (anonymized_text, mapping_dict) where mapping_dict
        maps the placeholder (e.g., "<PERSON_1>") to the original value.
    """
    entities = analyze_pii(text, score_threshold=0.0)
    
    if not entities:
        return text, {}

    # Sort descending by start position to avoid shifting indices when replacing
    entities.sort(key=lambda e: e.start, reverse=True)

    mapping: Dict[str, str] = {}
    reverse_mapping: Dict[str, str] = {} # original -> placeholder
    counters: Dict[str, int] = {}

    anonymized_text = text

    for entity in entities:
        original_value = entity.text_snippet
        
        # If we already encountered this exact string, reuse its placeholder
        if original_value in reverse_mapping:
            placeholder = reverse_mapping[original_value]
        else:
            # Generate new placeholder
            entity_type = entity.entity_type
            counters[entity_type] = counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{counters[entity_type]}>"
            
            mapping[placeholder] = original_value
            reverse_mapping[original_value] = placeholder

        # Replace in string using indices
        anonymized_text = (
            anonymized_text[:entity.start] 
            + placeholder 
            + anonymized_text[entity.end:]
        )

    return anonymized_text, mapping


def deanonymize(text: str, mapping: Dict[str, str]) -> str:
    """
    Restore original values in a text containing placeholders.

    Args:
        text: The text (e.g., LLM response) containing placeholders.
        mapping: The dictionary mapping placeholders to original values.

    Returns:
        The text with placeholders replaced by their original values.
    """
    if not text or not mapping:
        return text

    deanonymized_text = text
    # Simple replacement for all placeholders in the mapping
    # Note: A more robust approach might use regex to match exactly, but 
    # since our placeholders are highly specific (e.g., <PERSON_1>),
    # string replacement is generally safe.
    for placeholder, original_value in mapping.items():
        deanonymized_text = deanonymized_text.replace(placeholder, original_value)

    return deanonymized_text
