"""
tests/test_ollama.py
Day 6: OllamaProvider tests

Strategy:
- Use `respx` to mock httpx calls — no real Ollama server required.
- Inject fakeredis for rate-limit isolation (same pattern as Day 5 tests).
- Test the /chat endpoint end-to-end through FastAPI.
- Test OllamaProvider directly for error path coverage.

Run with: pytest tests/test_ollama.py -q
"""

import os
import json
import pytest
import respx
import httpx
import fakeredis
from fastapi.testclient import TestClient

import app.security.rate_limiter as rate_limiter_module
from app.main import app
from app.providers.ollama import OllamaProvider
from app.routes.basic_chat import _reset_ollama

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------




@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def auth_headers():
    return {"Authorization": "Bearer test-token"}


# ---------------------------------------------------------------------------
# Helper: build a realistic Ollama /api/chat response
# ---------------------------------------------------------------------------

def _ollama_response(content: str, model: str = "tinyllama") -> dict:
    return {
        "model": model,
        "created_at": "2024-01-01T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "total_duration": 123456789,
        "eval_count": 20,
    }


# ---------------------------------------------------------------------------
# 1. /chat endpoint — happy path
# ---------------------------------------------------------------------------

@respx.mock
def test_chat_returns_ollama_response(client, auth_headers):
    """Authenticated request → Ollama called → real response text returned."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response("Hello from Ollama!"))
    )
    resp = client.post("/chat", json={"prompt": "Say hello"}, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["response"] == "Hello from Ollama!"
    assert body["model"] == "tinyllama"


@respx.mock
def test_chat_response_includes_model_field(client, auth_headers):
    """Response body must include the `model` field so callers can verify the LLM."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response("Test response"))
    )
    resp = client.post("/chat", json={"prompt": "test"}, headers=auth_headers)
    assert resp.status_code == 200
    assert "model" in resp.json()


# ---------------------------------------------------------------------------
# 2. Authentication still enforced
# ---------------------------------------------------------------------------

def test_chat_no_auth_returns_401(client):
    resp = client.post("/chat", json={"prompt": "hello"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"


def test_chat_wrong_token_returns_401(client):
    resp = client.post(
        "/chat",
        json={"prompt": "hello"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid authentication token"


# ---------------------------------------------------------------------------
# 3. Input validation still enforced
# ---------------------------------------------------------------------------

@respx.mock
def test_empty_prompt_returns_400(client, auth_headers):
    resp = client.post("/chat", json={"prompt": "   "}, headers=auth_headers)
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 4. Ollama not running → 503
# ---------------------------------------------------------------------------

@respx.mock
def test_chat_ollama_not_running_returns_503(client, auth_headers):
    """Simulate Ollama server being down."""
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    resp = client.post("/chat", json={"prompt": "hello"}, headers=auth_headers)
    assert resp.status_code == 503
    assert "Ollama" in resp.json()["detail"]
    assert "ollama serve" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Ollama timeout → 504
# ---------------------------------------------------------------------------

@respx.mock
def test_chat_ollama_timeout_returns_504(client, auth_headers):
    """Simulate Ollama taking too long (large model loading on first call)."""
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ReadTimeout("Timeout")
    )
    resp = client.post("/chat", json={"prompt": "hello"}, headers=auth_headers)
    assert resp.status_code == 504
    assert "timed out" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. Ollama returns HTTP error (e.g. model not found)
# ---------------------------------------------------------------------------

@respx.mock
def test_chat_ollama_model_not_found_returns_500(client, auth_headers):
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(404, text='{"error": "model not found"}')
    )
    resp = client.post("/chat", json={"prompt": "hello"}, headers=auth_headers)
    assert resp.status_code == 500
    assert "Ollama API error" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 7. Rate limiting still enforced (10 req/min)
# ---------------------------------------------------------------------------

@respx.mock
def test_rate_limit_still_enforced(client, auth_headers):
    """After 10 requests, the 11th must return 429."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response("ok"))
    )
    for _ in range(10):
        r = client.post("/chat", json={"prompt": "hello"}, headers=auth_headers)
        assert r.status_code == 200

    r = client.post("/chat", json={"prompt": "hello"}, headers=auth_headers)
    assert r.status_code == 429
    assert "Rate limit exceeded" in r.json()["detail"]


# ---------------------------------------------------------------------------
# 8. /health/ollama endpoint
# ---------------------------------------------------------------------------

@respx.mock
def test_health_ollama_when_running(client):
    """Health check correctly reports Ollama as reachable."""
    tags_response = {
        "models": [
            {"name": "tinyllama:latest"},
            {"name": "phi3:mini"},
        ]
    }
    respx.get("http://localhost:11434/api/tags").mock(
        return_value=httpx.Response(200, json=tags_response)
    )
    resp = client.get("/health/ollama")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ollama_reachable"] is True
    assert body["model"] == "tinyllama"
    assert body["model_available"] is True


@respx.mock
def test_health_ollama_when_not_running(client):
    """Health check correctly reports Ollama as unreachable."""
    respx.get("http://localhost:11434/api/tags").mock(
        side_effect=httpx.ConnectError("refused")
    )
    resp = client.get("/health/ollama")
    assert resp.status_code == 200          # health endpoint itself stays up
    body = resp.json()
    assert body["ollama_reachable"] is False


# ---------------------------------------------------------------------------
# 9. /health still works with no auth (Day 1 regression)
# ---------------------------------------------------------------------------

def test_health_endpoint_unchanged(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}


# ---------------------------------------------------------------------------
# 10. OllamaProvider respects env vars
# ---------------------------------------------------------------------------

def test_ollama_provider_reads_env_vars():
    os.environ["OLLAMA_BASE_URL"] = "http://myserver:11434"
    os.environ["OLLAMA_MODEL"] = "phi3:mini"
    provider = OllamaProvider()
    assert provider.base_url == "http://myserver:11434"
    assert provider.model == "phi3:mini"
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    os.environ["OLLAMA_MODEL"] = "tinyllama"


def test_ollama_provider_default_env_vars():
    os.environ.pop("OLLAMA_BASE_URL", None)
    os.environ.pop("OLLAMA_MODEL", None)
    provider = OllamaProvider()
    assert provider.base_url == "http://localhost:11434"
    assert provider.model == "llama3.2:3b"
    # Restore
    os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    os.environ["OLLAMA_MODEL"] = "tinyllama"
