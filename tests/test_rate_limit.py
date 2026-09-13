"""
tests/test_rate_limit.py
Day 5: Redis Rate Limiting tests (updated for Day 6 Ollama backend)

All tests that expect HTTP 200 from /chat now mock the Ollama endpoint via
respx so no real Ollama server is needed during unit testing.
"""

import os
import pytest
import respx
import httpx
import fakeredis
from fastapi.testclient import TestClient

import app.security.rate_limiter as rate_limiter_module
from app.main import app

RATE_LIMIT = rate_limiter_module.RATE_LIMIT_REQUESTS  # 10

_OLLAMA_OK = {
    "model": "tinyllama",
    "message": {"role": "assistant", "content": "Mock Ollama response."},
    "done": True,
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_env_and_fake_redis():
    os.environ["GATEWAY_API_KEY"] = "test-token-abc"
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    os.environ["OLLAMA_MODEL"] = "tinyllama"

    fake = fakeredis.FakeRedis(decode_responses=True)
    rate_limiter_module.set_redis_client(fake)

    yield fake

    for key in ["GATEWAY_API_KEY", "OLLAMA_BASE_URL", "OLLAMA_MODEL"]:
        os.environ.pop(key, None)
    rate_limiter_module.reset_redis_client()


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def valid_headers():
    return {"Authorization": "Bearer test-token-abc"}


def _post_chat(client, headers, payload=None):
    if payload is None:
        payload = {"prompt": "hello"}
    return client.post("/chat", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestRateLimiting:

    # 1. Authenticated request within the limit → 200
    @respx.mock
    def test_single_request_within_limit(self, client, valid_headers):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        response = _post_chat(client, valid_headers)
        assert response.status_code == 200
        assert response.json()["success"] is True

    # 2. Multiple authenticated requests within the limit → 200
    @respx.mock
    def test_multiple_requests_within_limit(self, client, valid_headers):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        for i in range(RATE_LIMIT):
            response = _post_chat(client, valid_headers)
            assert response.status_code == 200, (
                f"Request {i + 1} should succeed but got {response.status_code}"
            )

    # 3. Request exceeding 10 requests/minute → 429
    @respx.mock
    def test_request_exceeding_limit_returns_429(self, client, valid_headers):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        for _ in range(RATE_LIMIT):
            r = _post_chat(client, valid_headers)
            assert r.status_code == 200

        # Rate limiter fires before Ollama is called — no mock needed for 429
        response = _post_chat(client, valid_headers)
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    # 3b. Retry-After header is present on 429
    @respx.mock
    def test_429_includes_retry_after_header(self, client, valid_headers):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        for _ in range(RATE_LIMIT):
            _post_chat(client, valid_headers)

        response = _post_chat(client, valid_headers)
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    # 4. Different authenticated users have separate rate limits
    @respx.mock
    def test_separate_limits_per_user(self, client, setup_env_and_fake_redis):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        user_a_headers = {"Authorization": "Bearer test-token-abc"}
        os.environ["GATEWAY_API_KEY"] = "test-token-abc"

        for _ in range(RATE_LIMIT):
            r = _post_chat(client, user_a_headers)
            assert r.status_code == 200

        r = _post_chat(client, user_a_headers)
        assert r.status_code == 429

        os.environ["GATEWAY_API_KEY"] = "test-token-xyz"
        user_b_headers = {"Authorization": "Bearer test-token-xyz"}
        r = _post_chat(client, user_b_headers)
        assert r.status_code == 200

        os.environ["GATEWAY_API_KEY"] = "test-token-abc"

    # 5. Unauthenticated request → 401 (no Ollama call needed)
    def test_unauthenticated_request_returns_401(self, client):
        response = _post_chat(client, headers={})
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    # 6. Invalid token → 401
    def test_invalid_token_returns_401(self, client):
        response = _post_chat(
            client,
            headers={"Authorization": "Bearer totally-wrong-token"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid authentication token"

    # 7. /health without authentication → 200 (no rate limiting)
    def test_health_endpoint_no_auth_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    # 7b. /health is NOT rate-limited even after many calls
    def test_health_not_rate_limited(self, client):
        for _ in range(RATE_LIMIT + 5):
            r = client.get("/health")
            assert r.status_code == 200

    # Extra: counter resets after window expires
    @respx.mock
    def test_counter_resets_after_window(self, client, valid_headers, setup_env_and_fake_redis):
        respx.post("http://localhost:11434/api/chat").mock(
            return_value=httpx.Response(200, json=_OLLAMA_OK)
        )
        fake_redis = setup_env_and_fake_redis

        for _ in range(RATE_LIMIT):
            _post_chat(client, valid_headers)

        r = _post_chat(client, valid_headers)
        assert r.status_code == 429

        key = rate_limiter_module._rate_limit_key("test-token-abc")
        fake_redis.delete(key)

        r = _post_chat(client, valid_headers)
        assert r.status_code == 200
