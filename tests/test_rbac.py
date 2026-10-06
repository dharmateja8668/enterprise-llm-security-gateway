"""
tests/test_rbac.py
Unit and Integration tests for Role-Based Access Control (RBAC).

Tests scenarios:
  1. Authorized user (Engineering / Cybersecurity employee) -> 200 OK
  2. Unauthorized user (HR employee) -> 403 Forbidden with exact error detail
  3. Admin user -> 200 OK
  4. Invalid API key -> 401 Unauthorized
  5. DB audit logging for rbac_blocked status
"""

import pytest
import respx
import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User
from app.models.rbac import RBACPolicy
from app.models.log import RequestLog
from tests.conftest import TestingSessionLocal

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer test-token"}


def _ollama_response(content: str = "Hello world!", model: str = "tinyllama") -> dict:
    return {
        "model": model,
        "created_at": "2026-10-03T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": True,
    }


@pytest.fixture
def setup_rbac_users_and_policies():
    """Create test users and policies in the test DB."""
    db: Session = TestingSessionLocal()
    try:
        # Clear existing users & policies to avoid collisions
        db.query(RBACPolicy).delete()
        db.query(User).delete()
        db.commit()

        # Seed RBAC Policies
        p1 = RBACPolicy(department="Engineering", role="employee", allowed_model="tinyllama")
        p2 = RBACPolicy(department="Engineering", role="employee", allowed_model="llama3.2:3b")
        p3 = RBACPolicy(department="Cybersecurity", role="employee", allowed_model="tinyllama")
        p4 = RBACPolicy(department="Cybersecurity", role="employee", allowed_model="llama3.2:3b")
        db.add_all([p1, p2, p3, p4])

        # Seed Test Users (distinct test usernames)
        u_eng = User(
            username="test_eng_user",
            email="eng@example.com",
            password_hash="secret",
            department="Engineering",
            role="employee",
        )
        u_hr = User(
            username="test_hr_user",
            email="hr@example.com",
            password_hash="secret",
            department="HR",
            role="employee",
        )
        u_admin = User(
            username="test_admin_user",
            email="admin@example.com",
            password_hash="secret",
            department="Executive",
            role="admin",
        )
        db.add_all([u_eng, u_hr, u_admin])
        db.commit()

        yield {
            "eng_user": u_eng,
            "hr_user": u_hr,
            "admin_user": u_admin,
        }
    finally:
        db.close()


# ==============================================================================
# TEST 1 — AUTHORIZED USER
# ==============================================================================
@respx.mock
def test_rbac_authorized_user(setup_rbac_users_and_policies):
    """Test 1: User with department Engineering has permission for tinyllama / llama3.2:3b -> 200 OK."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response("Access granted"))
    )

    resp = client.post(
        "/chat",
        json={"prompt": "Hello, world!", "user_id": "test_eng_user"},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is True


# ==============================================================================
# TEST 2 — UNAUTHORIZED USER
# ==============================================================================
def test_rbac_unauthorized_user(setup_rbac_users_and_policies):
    """Test 2: HR employee requesting access without permission -> 403 Forbidden with exact error payload."""
    resp = client.post(
        "/chat",
        json={"prompt": "Hello, world!", "user_id": "test_hr_user"},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["detail"]["error"] == "AI model access denied"
    assert data["detail"]["blocked"] is True
    assert data["detail"]["reason"] == "rbac_model_access_denied"

    # Verify audit log recorded rbac_blocked status and redacted prompt
    db = TestingSessionLocal()
    try:
        log_entry = db.query(RequestLog).filter(RequestLog.user_token == "test_hr_user").order_by(RequestLog.id.desc()).first()
        assert log_entry is not None
        assert log_entry.status == "rbac_blocked"
        assert "[REDACTED" in log_entry.prompt
    finally:
        db.close()


# ==============================================================================
# TEST 3 — ADMIN USER
# ==============================================================================
@respx.mock
def test_rbac_admin_user(setup_rbac_users_and_policies):
    """Test 3: Admin user accessing the configured model -> 200 OK."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response("Admin response"))
    )

    resp = client.post(
        "/chat",
        json={"prompt": "Hello admin!", "user_id": "test_admin_user"},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is True


# ==============================================================================
# TEST 4 — INVALID API KEY
# ==============================================================================
def test_rbac_invalid_api_key():
    """Test 4: Request with invalid API key -> 401 Unauthorized."""
    resp = client.post(
        "/chat",
        json={"prompt": "Hello", "user_id": "test_eng_user"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


# ==============================================================================
# TEST 5 — SOC DASHBOARD ROLE ACCESS
# ==============================================================================
def test_soc_analyst_dashboard_access(setup_rbac_users_and_policies):
    """Test 5: SOC Dashboard access control for ADMIN, SOC_ANALYST, EMPLOYEE, and FINANCE."""
    db = TestingSessionLocal()
    try:
        # Create users for all roles if not present
        u_analyst = User(
            username="test_soc_analyst",
            email="analyst@example.com",
            password_hash="secret",
            department="Security",
            role="soc_analyst",
        )
        u_emp = User(
            username="test_employee",
            email="employee@example.com",
            password_hash="secret",
            department="Operations",
            role="employee",
        )
        u_fin = User(
            username="test_finance",
            email="finance@example.com",
            password_hash="secret",
            department="Finance",
            role="finance",
        )
        db.add_all([u_analyst, u_emp, u_fin])
        db.commit()

        # 1. ADMIN -> 200 OK
        resp_admin = client.get("/dashboard?user_id=test_admin_user", headers=AUTH_HEADERS)
        assert resp_admin.status_code == 200
        assert resp_admin.json()["status"] == "success"

        resp_admin_metrics = client.get("/dashboard/metrics?user_id=test_admin_user", headers=AUTH_HEADERS)
        assert resp_admin_metrics.status_code == 200

        # 2. SOC_ANALYST -> 200 OK
        resp_analyst = client.get("/dashboard?user_id=test_soc_analyst", headers=AUTH_HEADERS)
        assert resp_analyst.status_code == 200
        assert resp_analyst.json()["status"] == "success"

        resp_analyst_metrics = client.get("/dashboard/metrics?user_id=test_soc_analyst", headers=AUTH_HEADERS)
        assert resp_analyst_metrics.status_code == 200

        resp_analyst_events = client.get("/dashboard/security-events?user_id=test_soc_analyst", headers=AUTH_HEADERS)
        assert resp_analyst_events.status_code == 200

        # 3. EMPLOYEE -> 403 Forbidden
        resp_emp = client.get("/dashboard?user_id=test_employee", headers=AUTH_HEADERS)
        assert resp_emp.status_code == 403
        assert resp_emp.json()["detail"]["blocked"] is True

        resp_emp_metrics = client.get("/dashboard/metrics?user_id=test_employee", headers=AUTH_HEADERS)
        assert resp_emp_metrics.status_code == 403

        # 4. FINANCE -> 403 Forbidden
        resp_fin = client.get("/dashboard?user_id=test_finance", headers=AUTH_HEADERS)
        assert resp_fin.status_code == 403
        assert resp_fin.json()["detail"]["blocked"] is True

        resp_fin_metrics = client.get("/dashboard/metrics?user_id=test_finance", headers=AUTH_HEADERS)
        assert resp_fin_metrics.status_code == 403
    finally:
        db.close()

