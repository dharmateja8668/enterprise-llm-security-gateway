"""
app/security/cache.py
Redis-backed response cache for LLM completions.

Provides deterministic exact response caching for sanitized prompts.
Reduces latency from ~1000ms+ to <5ms for duplicate requests, saves LLM provider token costs,
and operates safely with automatic fail-open semantics when Redis is unreachable or disabled.
"""

import hashlib
import logging
import os
from typing import Optional

from app.security.rate_limiter import get_redis

logger = logging.getLogger(__name__)

# Configurable via environment variable:
# Set RESPONSE_CACHE_ENABLED=true to activate response caching.
# Defaults to false to avoid interfering with unit test mocks when not explicitly enabled.
RESPONSE_CACHE_ENABLED: bool = os.getenv("RESPONSE_CACHE_ENABLED", "false").lower() == "true"
RESPONSE_CACHE_TTL_SECONDS: int = int(os.getenv("RESPONSE_CACHE_TTL_SECONDS", "3600"))  # 1 hour default


def is_cache_enabled() -> bool:
    """Return whether LLM response caching is enabled."""
    return os.getenv("RESPONSE_CACHE_ENABLED", "false").lower() == "true"


def generate_cache_key(
    provider: str,
    model: str,
    sanitized_prompt: str,
    user_scope: Optional[str] = None,
) -> str:
    """
    Generate a deterministic SHA-256 cache key scoped to provider, model, prompt, and optional user/tenant scope.
    Ensures safe, collision-resistant indexing and prevents cross-user/cross-tenant response leakage.
    """
    normalized_prompt = sanitized_prompt.strip()
    content_hash = hashlib.sha256(normalized_prompt.encode("utf-8")).hexdigest()
    user_part = hashlib.sha256(user_scope.encode("utf-8")).hexdigest()[:16] if user_scope else "global"
    return f"llm_cache:{provider.lower()}:{model.lower()}:{user_part}:{content_hash}"


def get_cached_response(
    provider: str,
    model: str,
    sanitized_prompt: str,
    user_scope: Optional[str] = None,
) -> Optional[str]:
    """
    Retrieve cached LLM response text if present in Redis.
    Fails open (returns None) on any Redis error or when caching is disabled.
    """
    if not is_cache_enabled():
        return None

    try:
        client = get_redis()
        if not client:
            return None
        key = generate_cache_key(provider, model, sanitized_prompt, user_scope)
        cached_value = client.get(key)
        if cached_value:
            logger.info("Response cache HIT for %s/%s (user_scope=%s)", provider, model, "yes" if user_scope else "global")
            return cached_value
    except Exception as exc:
        logger.debug("Response cache read failed (failing open): %s", exc)
    return None


def set_cached_response(
    provider: str,
    model: str,
    sanitized_prompt: str,
    response_text: str,
    ttl_seconds: int = RESPONSE_CACHE_TTL_SECONDS,
    user_scope: Optional[str] = None,
) -> bool:
    """
    Store an LLM response in Redis with a TTL.
    Fails open (returns False) on any Redis error or when caching is disabled.
    """
    if not is_cache_enabled() or not response_text:
        return False

    try:
        client = get_redis()
        if not client:
            return False
        key = generate_cache_key(provider, model, sanitized_prompt, user_scope)
        client.set(key, response_text, ex=ttl_seconds)
        logger.info("Response cache STORED for %s/%s (ttl=%ds, user_scope=%s)", provider, model, ttl_seconds, "yes" if user_scope else "global")
        return True
    except Exception as exc:
        logger.debug("Response cache write failed (failing open): %s", exc)
        return False


def clear_response_cache() -> int:
    """
    Clear all cached LLM responses from Redis (useful for administrative or testing tasks).
    """
    try:
        client = get_redis()
        if not client:
            return 0
        keys = client.keys("llm_cache:*")
        if keys:
            return client.delete(*keys)
    except Exception as exc:
        logger.debug("Failed to clear response cache: %s", exc)
    return 0
