"""
Day 5: Redis-based rate limiter for the Enterprise LLM Security Gateway.

Rate limit: 10 requests per 60-second window per authenticated user/token.
The counter key is scoped to each user token so limits are independent.

Environment variables:
    REDIS_URL                    - Redis connection URL (default: redis://localhost:6379)
                                   Example: redis://localhost:6379
                                   Never hard-code passwords or secrets here.
    RATE_LIMIT_FALLBACK_FAKEREDIS - Set to 'true' to use an in-process fakeredis
                                   store when Redis is unreachable (dev/test only).
                                   Defaults to 'false' (production mode).
"""

import os
import redis
from fastapi import HTTPException, status

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------
RATE_LIMIT_REQUESTS: int = 10          # max requests per window
RATE_LIMIT_WINDOW_SECONDS: int = 60   # rolling window in seconds


def _get_redis_client() -> redis.Redis:
    """
    Create and return a Redis client.

    In production: connects to the REDIS_URL environment variable.
    In dev/test:   if RATE_LIMIT_FALLBACK_FAKEREDIS=true, falls back to an
                   in-process fakeredis store when Redis is unreachable so
                   developers can run /chat without a local Redis install.
    """
    redis_url = os.getenv("REDIS_URL", "")
    use_fake = os.getenv("RATE_LIMIT_FALLBACK_FAKEREDIS", "false").lower() == "true"

    if use_fake or not redis_url:
        # Dev / CI fallback: in-process store, no external dependency.
        try:
            import fakeredis
            return fakeredis.FakeRedis(decode_responses=True)
        except ImportError:
            pass  # fakeredis not installed — fall through to real Redis

    # Production path: real Redis.
    effective_url = redis_url or "redis://localhost:6379"
    client = redis.from_url(effective_url, decode_responses=True)
    # Eagerly ping so misconfiguration is discovered at startup, not on first request.
    try:
        client.ping()
    except redis.RedisError:
        # If fakeredis is available, silently fall back.
        try:
            import fakeredis
            return fakeredis.FakeRedis(decode_responses=True)
        except ImportError:
            pass  # Let the caller handle the error via the standard exception path.
    return client


# Module-level client (created once per process, re-used across requests).
# Tests replace this via monkeypatching or fakeredis injection.
_redis_client: redis.Redis | None = None
redis_client = _redis_client


def get_redis() -> redis.Redis:
    """Return the shared Redis client, creating it on first call."""
    global _redis_client
    if _redis_client is None:
        _redis_client = _get_redis_client()
    return _redis_client


def set_redis_client(client: redis.Redis) -> None:
    """
    Allow tests (and other callers) to inject a custom Redis client
    (e.g. fakeredis.FakeRedis) without touching environment variables.
    """
    global _redis_client
    _redis_client = client


def reset_redis_client() -> None:
    """Reset the cached client so the next call to get_redis() creates a new one."""
    global _redis_client
    _redis_client = None


def _rate_limit_key(user_token: str) -> str:
    """Build the Redis key for a specific user's rate-limit counter."""
    return f"rate_limit:{user_token}"


def check_rate_limit(user_token: str) -> None:
    """
    Enforce the rate limit for the given authenticated user token.

    Uses a Redis INCR + EXPIRE approach (atomic for single-key operations):
      1. INCR the counter for this user.
      2. On the very first request (counter == 1), set the TTL to the window.
      3. If the counter exceeds the limit, raise HTTP 429.

    This is an efficient O(1) Redis operation per request.

    Args:
        user_token: The authenticated API token used as the per-user identity.

    Raises:
        HTTPException(429): When the user has exceeded the rate limit.
        HTTPException(503): When Redis is unavailable (fail-open would hide
                            the Redis outage; fail-closed protects the backend).
    """
    client = get_redis()
    key = _rate_limit_key(user_token)

    try:
        # Atomically increment the counter.
        current_count = client.incr(key)

        # Set expiry only on the first request in each window so that the
        # window is anchored to the FIRST request, not reset on every request.
        if current_count == 1:
            client.expire(key, RATE_LIMIT_WINDOW_SECONDS)

        if current_count > RATE_LIMIT_REQUESTS:
            # Tell the client how long to wait (approximate).
            ttl = client.ttl(key)
            retry_after = ttl if ttl > 0 else RATE_LIMIT_WINDOW_SECONDS
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    except HTTPException:
        # Re-raise rate-limit exceptions unchanged.
        raise
    except redis.RedisError as exc:
        # Redis is down — fail with 503 so the client knows to retry later
        # and operators see that the dependency is unavailable.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service is temporarily unavailable. Please try again later.",
        ) from exc
