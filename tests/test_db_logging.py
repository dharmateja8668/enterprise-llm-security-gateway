import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_db
from app.models.log import RequestLog
import respx
import httpx
from app.routes.basic_chat import _token_identifier
from tests.conftest import TestingSessionLocal

client = TestClient(app)

def test_db_configuration():
    """Verify the database tables are created and model is correct."""
    db = TestingSessionLocal()
    try:
        # Should start empty
        logs = db.query(RequestLog).all()
        assert len(logs) == 0
    finally:
        db.close()


@respx.mock
def test_successful_request_is_logged():
    """Verify that a successful chat request creates a database record with no raw token."""
    # Mock Ollama response
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "model": "tinyllama",
            "message": {"role": "assistant", "content": "Ollama response"},
            "done": True
        })
    )
    
    # Send request
    prompt = "Test logging prompt"
    token = "test-token"
    response = client.post("/chat", json={"prompt": prompt}, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Check database
    db = TestingSessionLocal()
    try:
        logs = db.query(RequestLog).all()
        assert len(logs) == 1
        log = logs[0]
        
        # Verify fields
        assert log.id is not None
        assert log.request_id is not None
        assert len(log.request_id) > 10
        assert log.provider == "ollama"
        assert log.model == "tinyllama"
        assert log.prompt == prompt
        assert log.status == "success"
        
        # Security verification: raw token must NOT be stored
        assert log.user_token != token
        assert log.user_token == _token_identifier(token)
    finally:
        db.close()


@respx.mock
def test_failed_request_is_logged_as_error():
    """Verify that a failed chat request creates a database record with status='error'."""
    # Mock Ollama response to fail
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    
    # Send request
    prompt = "Test error logging prompt"
    token = "test-token"
    response = client.post("/chat", json={"prompt": prompt}, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 503
    
    # Check database
    db = TestingSessionLocal()
    try:
        logs = db.query(RequestLog).filter(RequestLog.prompt == prompt).all()
        assert len(logs) == 1
        log = logs[0]
        
        # Verify fields
        assert log.status == "error"
        assert log.provider == "ollama"
    finally:
        db.close()
