import os
import pytest
import fakeredis
from fastapi.testclient import TestClient
from app.main import app
import app.security.rate_limiter as rate_limiter_module

client = TestClient(app)

@pytest.fixture(autouse=True)
def set_env():
    """Set the API key and inject a fake Redis so rate limiting doesn't need a real server."""
    os.environ["GATEWAY_API_KEY"] = "secret-token-123"
    # Inject an in-memory Redis so auth tests don't fail due to Redis being unavailable
    fake = fakeredis.FakeRedis(decode_responses=True)
    rate_limiter_module.set_redis_client(fake)
    yield
    del os.environ["GATEWAY_API_KEY"]
    rate_limiter_module.reset_redis_client()

def test_chat_no_auth():
    response = client.post("/chat", json={"prompt": "test"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"

def test_chat_invalid_token():
    response = client.post("/chat", json={"prompt": "test"}, headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication token"

def test_chat_valid_token():
    response = client.post("/chat", json={"prompt": "test"}, headers={"Authorization": "Bearer secret-token-123"})
    assert response.status_code == 200
    assert response.json()["success"] is True

def test_health_no_auth():
    response = client.get("/health")
    assert response.status_code == 200
