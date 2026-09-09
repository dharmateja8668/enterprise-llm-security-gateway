import pytest
from fastapi.testclient import TestClient
from app.main import app
from unittest.mock import patch
from app.models.schemas import ChatResponse
import uuid

client = TestClient(app)

def test_chat_validation_error():
    # Missing provider
    response = client.post("/v1/chat/completions", json={
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    })
    assert response.status_code == 422

def test_invalid_provider():
    response = client.post("/v1/chat/completions", json={
        "provider": "unknown_provider",
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    })
    assert response.status_code == 400
    assert "Unsupported provider" in response.json()["detail"]

@patch("app.providers.openai.OpenAIProvider.chat_completions")
def test_valid_request_openai(mock_chat_completions):
    mock_chat_completions.return_value = ChatResponse(
        id=str(uuid.uuid4()),
        provider="openai",
        model="gpt-4o",
        choices=[{"message": {"role": "assistant", "content": "Hi!"}}]
    )
    
    response = client.post("/v1/chat/completions", json={
        "provider": "openai",
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "openai"
    assert len(data["choices"]) == 1
    assert data["choices"][0]["message"]["content"] == "Hi!"
