import os
import pytest
import respx
import httpx
import fakeredis
from fastapi.testclient import TestClient
from app.main import app
import app.security.rate_limiter as rate_limiter_module

client = TestClient(app)

# Minimal Ollama response used whenever a 200 is expected
_OLLAMA_OK = {
    "model": "tinyllama",
    "message": {"role": "assistant", "content": "Test response from Ollama."},
    "done": True,
}



def test_chat_no_auth():
    response = client.post("/chat", json={"prompt": "test"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"

def test_chat_invalid_token():
    response = client.post("/chat", json={"prompt": "test"}, headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication token"

@respx.mock
def test_chat_valid_token():
    """Valid auth → Ollama called → 200."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_OLLAMA_OK)
    )
    response = client.post("/chat", json={"prompt": "test"}, headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.json()["success"] is True

def test_health_no_auth():
    response = client.get("/health")
    assert response.status_code == 200
