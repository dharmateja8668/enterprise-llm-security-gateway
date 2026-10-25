"""
tests/test_response_cache.py
Verification test suite for Redis-backed LLM response caching and fail-open semantics.
"""

import os
import fakeredis
import pytest
import respx
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.security import cache
from app.security import rate_limiter

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_fakeredis():
    """Ensure FakeRedis is used for caching tests."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    rate_limiter.set_redis_client(fake)
    yield fake
    rate_limiter.reset_redis_client()
    cache.clear_response_cache()


def test_cache_disabled_by_default(monkeypatch):
    """By default, response caching is disabled to avoid side effects."""
    monkeypatch.delenv("RESPONSE_CACHE_ENABLED", raising=False)
    assert cache.is_cache_enabled() is False
    assert cache.get_cached_response("ollama", "llama3.2:3b", "Hello") is None


def test_generate_cache_key():
    """Verify deterministic SHA-256 hash formatting for cache keys."""
    key1 = cache.generate_cache_key("Ollama", "Llama3.2:3b", "What is quantum computing?")
    key2 = cache.generate_cache_key("ollama", "llama3.2:3b", "What is quantum computing?")
    assert key1 == key2
    assert key1.startswith("llm_cache:ollama:llama3.2:3b:")
    assert len(key1.split(":")[-1]) == 64  # SHA-256 hex length


def test_response_cache_read_write(monkeypatch, setup_fakeredis):
    """Verify caching and retrieving LLM responses when enabled."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")
    assert cache.is_cache_enabled() is True

    provider = "ollama"
    model = "llama3.2:3b"
    prompt = "Summarize the report"
    response_text = "This is a summarized report from the cached model."

    # Initial get should be a miss
    assert cache.get_cached_response(provider, model, prompt) is None

    # Store in cache
    success = cache.set_cached_response(provider, model, prompt, response_text, ttl_seconds=300)
    assert success is True

    # Retrieve from cache
    cached_val = cache.get_cached_response(provider, model, prompt)
    assert cached_val == response_text


def test_response_cache_clear(monkeypatch, setup_fakeredis):
    """Verify clear_response_cache removes only gateway LLM cache keys."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")

    cache.set_cached_response("ollama", "m1", "p1", "r1")
    cache.set_cached_response("openai", "m2", "p2", "r2")
    # Non-cache key
    setup_fakeredis.set("rate_limit:user1", "5")

    deleted = cache.clear_response_cache()
    assert deleted >= 2
    assert cache.get_cached_response("ollama", "m1", "p1") is None
    assert cache.get_cached_response("openai", "m2", "p2") is None
    # Rate limit key should be preserved
    assert setup_fakeredis.get("rate_limit:user1") == "5"


def test_response_cache_fail_open(monkeypatch):
    """Verify cache operations fail open (return None / False) on Redis errors."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")

    class BrokenRedis:
        def get(self, *args, **kwargs):
            raise ConnectionError("Redis is unreachable")

        def set(self, *args, **kwargs):
            raise ConnectionError("Redis is unreachable")

    rate_limiter.set_redis_client(BrokenRedis())
    assert cache.get_cached_response("ollama", "m", "p") is None
    assert cache.set_cached_response("ollama", "m", "p", "r") is False


@respx.mock
def test_chat_endpoint_hits_cache_when_enabled(monkeypatch, setup_fakeredis):
    """Verify /chat serves cached responses on identical queries without querying provider."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")
    monkeypatch.setenv("GATEWAY_API_KEY", "test-token")
    headers = {"Authorization": "Bearer test-token"}

    # Mock provider response for first call
    route = respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "model": "llama3.2:3b",
            "message": {"role": "assistant", "content": "Original computed response."},
            "done": True
        })
    )

    payload = {"prompt": "Tell me a joke about algorithms."}

    # First request: Cache Miss -> Calls Ollama Provider
    resp1 = client.post("/chat", json=payload, headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["response"] == "Original computed response."
    assert route.call_count == 1

    # Second request: Cache Hit -> Served from Redis without hitting Ollama
    resp2 = client.post("/chat", json=payload, headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["response"] == "Original computed response."
    assert route.call_count == 1  # Route was NOT called a second time


def test_user_cache_isolation(monkeypatch, setup_fakeredis):
    """Verify that cached responses cannot cross user or tenant boundaries."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")

    cache.set_cached_response(
        provider="ollama",
        model="llama3.2:3b",
        sanitized_prompt="Confidential query",
        response_text="Alice confidential output",
        user_scope="alice_tenant_1",
    )

    # Bob in another tenant or account should NOT get Alice's cached response
    bob_cached = cache.get_cached_response(
        provider="ollama",
        model="llama3.2:3b",
        sanitized_prompt="Confidential query",
        user_scope="bob_tenant_2",
    )
    assert bob_cached is None

    # Alice gets her cached response
    alice_cached = cache.get_cached_response(
        provider="ollama",
        model="llama3.2:3b",
        sanitized_prompt="Confidential query",
        user_scope="alice_tenant_1",
    )
    assert alice_cached == "Alice confidential output"


@respx.mock
def test_zero_pii_caching_invariant(monkeypatch, setup_fakeredis):
    """
    AppSec Invariant: Prompts containing sensitive PII must NEVER be cached in Redis.
    Each PII request must be processed live and never stored in the shared cache.
    """
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")
    monkeypatch.setenv("GATEWAY_API_KEY", "test-token")
    headers = {"Authorization": "Bearer test-token"}

    route = respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "model": "llama3.2:3b",
            "message": {"role": "assistant", "content": "Acknowledged <PII_PHONE_NUMBER_1>."},
            "done": True
        })
    )

    pii_payload = {"prompt": "Please verify my phone number 415-555-2671."}

    # Request 1: Contains PII
    resp1 = client.post("/chat", json=pii_payload, headers=headers)
    assert resp1.status_code == 200
    assert route.call_count == 1

    # Verify that NO Redis cache key was created for this prompt
    cached_keys = setup_fakeredis.keys("llm_cache:*")
    assert len(cached_keys) == 0, f"PII prompt was improperly cached: {cached_keys}"

    # Request 2: Repeating the same PII request must NOT hit cache
    resp2 = client.post("/chat", json=pii_payload, headers=headers)
    assert resp2.status_code == 200
    assert route.call_count == 2  # Provider was called again because cache was bypassed


@respx.mock
def test_api_user_isolation_prevents_cache_sharing(monkeypatch, setup_fakeredis):
    """Verify that two different users sending identical prompts do not share cache entries."""
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "true")
    monkeypatch.setenv("GATEWAY_API_KEY", "test-token")
    headers = {"Authorization": "Bearer test-token"}

    route = respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "model": "llama3.2:3b",
            "message": {"role": "assistant", "content": "BFS explanation."},
            "done": True
        })
    )

    # User A query
    payload_a = {"prompt": "Explain BFS algorithm", "user_id": "alice"}
    resp_a = client.post("/chat", json=payload_a, headers=headers)
    assert resp_a.status_code == 200
    assert route.call_count == 1

    # User B sends identical prompt -> Should NOT hit Alice's cache due to user scoping
    payload_b = {"prompt": "Explain BFS algorithm", "user_id": "bob"}
    resp_b = client.post("/chat", json=payload_b, headers=headers)
    assert resp_b.status_code == 200
    assert route.call_count == 2

    # User A repeats prompt -> Hits Alice's cache
    resp_a_repeat = client.post("/chat", json=payload_a, headers=headers)
    assert resp_a_repeat.status_code == 200
    assert route.call_count == 2  # Not incremented

