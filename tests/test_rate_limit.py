"""
tests/test_rate_limit.py
Day 5: Redis Rate Limiting tests

Strategy:
- Use fakeredis.FakeRedis as a drop-in Redis replacement — no real Redis needed.
- Inject the fake client via rate_limiter.set_redis_client() before each test.
- Reset after each test so counters do not bleed between tests.

All 8 required scenarios are covered:
  1. Authenticated request within the limit → 200
  2. Multiple authenticated requests within the limit → 200
  3. Request exceeding 10 req/min → 429
  4. Different authenticated users have separate limits
  5. Unauthenticated request → 401
  6. Invalid token → 401
  7. /health without authentication → 200
  8. Existing Day 1-4 tests must continue passing (covered by other test files)
"""

import os
import pytest
import fakeredis
from fastapi.testclient import TestClient

import app.security.rate_limiter as rate_limiter_module
from app.main import app

# ---------------------------------------------------------------------------
# Constants mirrored from the rate limiter so tests stay in sync automatically
# ---------------------------------------------------------------------------
RATE_LIMIT = rate_limiter_module.RATE_LIMIT_REQUESTS  # 10

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_env_and_fake_redis():
    """
    Before each test:
      - Set GATEWAY_API_KEY so authentication succeeds.
      - Inject a fresh FakeRedis instance (in-memory, no network).
    After each test:
      - Remove GATEWAY_API_KEY.
      - Reset the rate-limiter's cached client so tests are isolated.
    """
    os.environ["GATEWAY_API_KEY"] = "test-token-abc"

    fake = fakeredis.FakeRedis(decode_responses=True)
    rate_limiter_module.set_redis_client(fake)

    yield fake  # tests can access the fake client if needed

    del os.environ["GATEWAY_API_KEY"]
    rate_limiter_module.reset_redis_client()


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def valid_headers():
    return {"Authorization": "Bearer test-token-abc"}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _post_chat(client, headers, payload=None):
    if payload is None:
        payload = {"prompt": "hello"}
    return client.post("/chat", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestRateLimiting:

    # 1. Authenticated request within the limit → 200
    def test_single_request_within_limit(self, client, valid_headers):
        response = _post_chat(client, valid_headers)
        assert response.status_code == 200
        assert response.json()["success"] is True

    # 2. Multiple authenticated requests within the limit → 200
    def test_multiple_requests_within_limit(self, client, valid_headers):
        for i in range(RATE_LIMIT):
            response = _post_chat(client, valid_headers)
            assert response.status_code == 200, (
                f"Request {i + 1} should succeed but got {response.status_code}"
            )

    # 3. Request exceeding 10 requests/minute → 429
    def test_request_exceeding_limit_returns_429(self, client, valid_headers):
        # Send exactly RATE_LIMIT requests — all should pass
        for _ in range(RATE_LIMIT):
            r = _post_chat(client, valid_headers)
            assert r.status_code == 200

        # The (RATE_LIMIT + 1)-th request must be rejected
        response = _post_chat(client, valid_headers)
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    # 3b. Retry-After header is present on 429
    def test_429_includes_retry_after_header(self, client, valid_headers):
        for _ in range(RATE_LIMIT):
            _post_chat(client, valid_headers)

        response = _post_chat(client, valid_headers)
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    # 4. Different authenticated users have separate rate limits
    def test_separate_limits_per_user(self, client, setup_env_and_fake_redis):
        """
        User A exhausts their quota.
        User B (a different token) should still succeed.
        """
        user_a_headers = {"Authorization": "Bearer test-token-abc"}
        # Temporarily allow a second valid token by patching the env
        os.environ["GATEWAY_API_KEY"] = "test-token-abc"

        # Exhaust User A's quota
        for _ in range(RATE_LIMIT):
            r = _post_chat(client, user_a_headers)
            assert r.status_code == 200

        # User A is now rate-limited
        r = _post_chat(client, user_a_headers)
        assert r.status_code == 429

        # User B uses a different key — inject it
        os.environ["GATEWAY_API_KEY"] = "test-token-xyz"
        user_b_headers = {"Authorization": "Bearer test-token-xyz"}
        r = _post_chat(client, user_b_headers)
        # User B should NOT be affected by User A's counter
        assert r.status_code == 200

        # Restore for teardown
        os.environ["GATEWAY_API_KEY"] = "test-token-abc"

    # 5. Unauthenticated request → existing 401 behaviour
    def test_unauthenticated_request_returns_401(self, client):
        response = _post_chat(client, headers={})
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    # 6. Invalid token → existing 401 behaviour
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

    # Extra: 429 counter resets once Redis key expires (simulate via fake redis)
    def test_counter_resets_after_window(self, client, valid_headers, setup_env_and_fake_redis):
        """
        After the Redis key expires the user can make requests again.
        """
        fake_redis = setup_env_and_fake_redis

        # Exhaust the limit
        for _ in range(RATE_LIMIT):
            _post_chat(client, valid_headers)

        r = _post_chat(client, valid_headers)
        assert r.status_code == 429

        # Simulate window expiry by deleting the key directly
        key = rate_limiter_module._rate_limit_key("test-token-abc")
        fake_redis.delete(key)

        # Now the user should be able to make requests again
        r = _post_chat(client, valid_headers)
        assert r.status_code == 200
