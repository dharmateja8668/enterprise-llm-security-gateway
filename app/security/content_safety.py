"""
app/security/content_safety.py
Week 3 - Day 3: Content Safety Filters.
"""
import os
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ContentSafetyResult:
    safe: bool
    category: str
    severity: str
    reason: str
    score: float

def _content_safety_enabled() -> bool:
    """Return True if content safety is enabled."""
    return os.getenv("CONTENT_SAFETY_ENABLED", "true").lower() == "true"

def _content_safety_threshold() -> float:
    """Return the configured risk-score threshold."""
    try:
        value = float(os.getenv("CONTENT_SAFETY_THRESHOLD", "0.7"))
        return max(0.0, min(1.0, value))
    except ValueError:
        logger.warning("Invalid CONTENT_SAFETY_THRESHOLD value; using default 0.7")
        return 0.7

# Categories and patterns for identifying dangerous content.
# Patterns are specific enough to avoid matching standard security definitions.
_MALICIOUS_PATTERNS = [
    (
        "destructive_commands",
        "high",
        re.compile(
            r"(rm\s+-rf\s+/[a-zA-Z]*|mkfs\.[a-z0-9]+|dd\s+if=/dev/zero\s+of=/dev/[a-z]+|echo\s+c\s+>\s+/proc/sysrq-trigger)",
            re.IGNORECASE
        )
    ),
    (
        "reverse_shell",
        "high",
        re.compile(
            r"(nc\s+-e\s+/bin/(ba)?sh|/bin/(ba)?sh\s+-i\s+>&\s+/dev/tcp/|powershell\s+-nop\s+-w\s+hidden\s+-c)",
            re.IGNORECASE
        )
    ),
    (
        "credential_stealing",
        "high",
        re.compile(
            r"(sekurlsa::logonpasswords)",
            re.IGNORECASE
        )
    ),
]

def check_content_safety(response_text: str) -> ContentSafetyResult:
    """
    Inspect the generated LLM response for safety violations.
    Returns a structured result.
    """
    if not _content_safety_enabled() or not response_text:
        return ContentSafetyResult(
            safe=True,
            category="none",
            severity="none",
            reason="safe",
            score=0.0
        )

    try:
        # Check against malicious heuristics
        for category, severity, pattern in _MALICIOUS_PATTERNS:
            if pattern.search(response_text):
                logger.warning(f"Content safety violation detected: {category}")
                return ContentSafetyResult(
                    safe=False,
                    category=category,
                    severity=severity,
                    reason=f"Generated response contains a potentially destructive system command or payload.",
                    score=1.0
                )
        
        return ContentSafetyResult(
            safe=True,
            category="none",
            severity="none",
            reason="safe",
            score=0.0
        )
    except Exception as exc:
        logger.error(f"Unexpected error in content safety checking: {exc}", exc_info=True)
        # Fail closed on unexpected errors to maintain security
        return ContentSafetyResult(
            safe=False,
            category="internal_error",
            severity="high",
            reason="internal_error_fail_closed",
            score=1.0
        )
