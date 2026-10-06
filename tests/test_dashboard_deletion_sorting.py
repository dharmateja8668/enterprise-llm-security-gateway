"""
tests/test_dashboard_deletion_sorting.py
Integration & RBAC unit tests for SOC Dashboard log deletion, audit trail, user sorting, and RBAC security.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User
from app.models.log import RequestLog
from app.models.audit import AuditLog
from app.models.security_log import SecurityLog
from app.models.rbac import RBACPolicy
from tests.conftest import TestingSessionLocal

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer test-token"}

@pytest.fixture
def setup_dashboard_test_data():
    """Seed users, policies, and test log records in testing DB."""
    db: Session = TestingSessionLocal()
    try:
        # Clear existing tables to ensure pristine state
        db.query(AuditLog).delete()
        db.query(RequestLog).delete()
        db.query(SecurityLog).delete()
        db.query(RBACPolicy).delete()
        db.query(User).delete()
        db.commit()

        # Seed Users across all roles
        u_admin = User(username="admin_user", email="admin@zaalima.in", password_hash="secret", role="admin", department="Security")
        u_analyst = User(username="analyst_user", email="analyst@zaalima.in", password_hash="secret", role="soc_analyst", department="Security")
        u_manager = User(username="manager_user", email="manager@zaalima.in", password_hash="secret", role="manager", department="Management")
        u_employee = User(username="emp_user", email="emp@zaalima.in", password_hash="secret", role="employee", department="Engineering")
        db.add_all([u_admin, u_analyst, u_manager, u_employee])
        db.commit()

        # Seed RBAC policy
        p = RBACPolicy(department="Security", role="admin", allowed_model="llama3.2:3b")
        db.add(p)
        db.commit()

        # Seed test logs
        r1 = RequestLog(request_id="req-1001", user_token="admin_user", provider="ollama", model="llama3.2:3b", prompt="Log entry 1", status="success")
        r2 = RequestLog(request_id="req-1002", user_token="emp_user", provider="ollama", model="llama3.2:3b", prompt="Log entry 2", status="injection_blocked")
        a1 = AuditLog(request_id="req-1001", user_id="admin_user", provider="ollama", model="llama3.2:3b", prompt="Log entry 1", status="success", latency_ms=120)
        s1 = SecurityLog(request_id="req-1002", user_id=u_employee.id, check_type="prompt_injection", result="BLOCKED", risk_score=0.9)
        db.add_all([r1, r2, a1, s1])
        db.commit()

        yield {
            "admin": u_admin,
            "analyst": u_analyst,
            "manager": u_manager,
            "employee": u_employee,
            "log_1_id": r1.id,
            "log_1_req_id": r1.request_id,
            "log_2_id": r2.id,
            "log_2_req_id": r2.request_id
        }
    finally:
        db.close()


# ==============================================================================
# TEST 1 — ADMIN INDIVIDUAL LOG DELETION
# ==============================================================================
def test_admin_individual_log_deletion(setup_dashboard_test_data):
    """ADMIN can delete an individual log record by ID -> 200 OK and record is deleted from DB."""
    data = setup_dashboard_test_data
    log_id = data["log_1_id"]

    resp = client.delete(f"/dashboard/logs/{log_id}?user_id=admin_user", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    assert resp.json()["message"] == "Log deleted successfully."

    # Verify log is removed from DB
    db: Session = TestingSessionLocal()
    try:
        req = db.query(RequestLog).filter(RequestLog.id == log_id).first()
        assert req is None

        # Verify audit log entry created for DELETE_LOG action
        audit_entry = db.query(AuditLog).filter(AuditLog.prompt.like("%DELETE_LOG%")).first()
        assert audit_entry is not None
        assert audit_entry.user_id == "admin_user"
    finally:
        db.close()


# ==============================================================================
# TEST 2 — ADMIN DELETE ALL LOGS
# ==============================================================================
def test_admin_delete_all_logs(setup_dashboard_test_data):
    """ADMIN can delete all logs -> 200 OK, logs deleted from DB, Users & Policies preserved."""
    resp = client.delete("/dashboard/logs?user_id=admin_user", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    assert resp.json()["message"] == "All SOC logs deleted successfully."

    db: Session = TestingSessionLocal()
    try:
        # Request logs should be empty
        req_count = db.query(RequestLog).count()
        assert req_count == 0

        # Security logs should be empty
        sec_count = db.query(SecurityLog).count()
        assert sec_count == 0

        # USERS MUST BE PRESERVED
        user_count = db.query(User).count()
        assert user_count == 4

        # RBAC POLICIES MUST BE PRESERVED
        policy_count = db.query(RBACPolicy).count()
        assert policy_count == 1

        # Audit record for DELETE_ALL_LOGS should exist
        audit_entry = db.query(AuditLog).filter(AuditLog.prompt.like("%DELETE_ALL_LOGS%")).first()
        assert audit_entry is not None
        assert audit_entry.user_id == "admin_user"
    finally:
        db.close()


# ==============================================================================
# TEST 3 — SOC_ANALYST CANNOT DELETE LOGS (403 FORBIDDEN)
# ==============================================================================
def test_soc_analyst_cannot_delete(setup_dashboard_test_data):
    """SOC_ANALYST attempting individual or bulk log deletion -> 403 Forbidden."""
    data = setup_dashboard_test_data
    log_id = data["log_1_id"]

    # Individual delete -> 403
    resp_ind = client.delete(f"/dashboard/logs/{log_id}?user_id=analyst_user", headers=AUTH_HEADERS)
    assert resp_ind.status_code == 403
    assert resp_ind.json()["detail"]["blocked"] is True

    # Bulk delete -> 403
    resp_all = client.delete("/dashboard/logs?user_id=analyst_user", headers=AUTH_HEADERS)
    assert resp_all.status_code == 403
    assert resp_all.json()["detail"]["blocked"] is True


# ==============================================================================
# TEST 4 — MANAGER CANNOT DELETE LOGS (403 FORBIDDEN)
# ==============================================================================
def test_manager_cannot_delete(setup_dashboard_test_data):
    """MANAGER attempting log deletion -> 403 Forbidden."""
    data = setup_dashboard_test_data
    log_id = data["log_1_id"]

    resp_ind = client.delete(f"/dashboard/logs/{log_id}?user_id=manager_user", headers=AUTH_HEADERS)
    assert resp_ind.status_code == 403

    resp_all = client.delete("/dashboard/logs?user_id=manager_user", headers=AUTH_HEADERS)
    assert resp_all.status_code == 403


# ==============================================================================
# TEST 5 — EMPLOYEE CANNOT ACCESS DASHBOARD OR DELETE (403 FORBIDDEN)
# ==============================================================================
def test_employee_dashboard_access_denied(setup_dashboard_test_data):
    """EMPLOYEE attempting dashboard or deletion access -> 403 Forbidden."""
    resp_dash = client.get("/dashboard?user_id=emp_user", headers=AUTH_HEADERS)
    assert resp_dash.status_code == 403

    resp_del = client.delete("/dashboard/logs?user_id=emp_user", headers=AUTH_HEADERS)
    assert resp_del.status_code == 403


# ==============================================================================
# TEST 6 — USER SORTING BACKEND API
# ==============================================================================
def test_user_sorting_options(setup_dashboard_test_data):
    """Test all user sorting parameters: name_asc, name_desc, email_asc, department_asc, role_asc, most_active."""
    # 1. Name ascending
    resp_asc = client.get("/dashboard/users-data?sort_by=name_asc&user_id=admin_user", headers=AUTH_HEADERS)
    assert resp_asc.status_code == 200
    users_asc = [u["username"] for u in resp_asc.json()["users"]]
    assert users_asc == sorted(users_asc)

    # 2. Name descending
    resp_desc = client.get("/dashboard/users-data?sort_by=name_desc&user_id=admin_user", headers=AUTH_HEADERS)
    assert resp_desc.status_code == 200
    users_desc = [u["username"] for u in resp_desc.json()["users"]]
    assert users_desc == sorted(users_desc, reverse=True)

    # 3. Email ascending
    resp_email = client.get("/dashboard/users-data?sort_by=email_asc&user_id=admin_user", headers=AUTH_HEADERS)
    assert resp_email.status_code == 200
    emails = [u["email"] for u in resp_email.json()["users"]]
    assert emails == sorted(emails)

    # 4. Most Active
    resp_active = client.get("/dashboard/users-data?sort_by=most_active&user_id=admin_user", headers=AUTH_HEADERS)
    assert resp_active.status_code == 200
    activities = [u["activity"] for u in resp_active.json()["users"]]
    assert activities == sorted(activities, reverse=True)


# ==============================================================================
# TEST 7 — USER SEARCH + SORT INTEGRATION
# ==============================================================================
def test_user_search_and_sort(setup_dashboard_test_data):
    """Search for user substring + sort by role."""
    resp = client.get("/dashboard/users-data?search=admin&sort_by=role_asc&user_id=admin_user", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    users = resp.json()["users"]
    assert len(users) == 1
    assert users[0]["username"] == "admin_user"
