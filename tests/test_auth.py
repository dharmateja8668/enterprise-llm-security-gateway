import os
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def set_env():
    os.environ["GATEWAY_API_KEY"] = "secret-token-123"
    yield
    del os.environ["GATEWAY_API_KEY"]

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
