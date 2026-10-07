"""
scratch/test_roles_dashboard.py
Test role authentication and SOC dashboard backend access for all 4 roles.
"""

import os
from fastapi.testclient import TestClient

os.environ["GATEWAY_API_KEY"] = "dev-gateway-key-llama3"

from app.main import app

client = TestClient(app)

def test_all_roles_login_and_dashboard():
    print("=== TESTING ROLE AUTHENTICATION & DASHBOARD RBAC ===")

    # 1. Security Analyst Login & Dashboard Check
    res_analyst_login = client.post("/auth/login", json={"username_or_email": "analyst@zaalima.in", "password": "Analyst@123"})
    assert res_analyst_login.status_code == 200, f"Analyst login failed: {res_analyst_login.text}"
    analyst_user = res_analyst_login.json()["user"]
    print(f"[PASS] Security Analyst Login OK: username={analyst_user['username']}, role={analyst_user['role']}")

    res_analyst_dash = client.get(f"/dashboard/metrics?user_id={analyst_user['username']}")
    assert res_analyst_dash.status_code == 200, f"Analyst dashboard metrics failed: {res_analyst_dash.text}"
    print(f"[PASS] Security Analyst Dashboard Access: HTTP 200 OK (total_requests={res_analyst_dash.json()['total_requests']})")

    res_analyst_events = client.get(f"/dashboard/security-events?user_id={analyst_user['username']}")
    assert res_analyst_events.status_code == 200, f"Analyst security events failed: {res_analyst_events.text}"
    print(f"[PASS] Security Analyst Security Events API: HTTP 200 OK ({len(res_analyst_events.json())} events returned)")

    # 2. Administrator Login & Dashboard Check
    res_admin_login = client.post("/auth/login", json={"username_or_email": "admin@zaalima.in", "password": "Admin@123"})
    assert res_admin_login.status_code == 200, f"Admin login failed: {res_admin_login.text}"
    admin_user = res_admin_login.json()["user"]
    print(f"[PASS] Administrator Login OK: username={admin_user['username']}, role={admin_user['role']}")

    res_admin_dash = client.get(f"/dashboard/metrics?user_id={admin_user['username']}")
    assert res_admin_dash.status_code == 200, f"Admin dashboard metrics failed: {res_admin_dash.text}"
    print(f"[PASS] Administrator Dashboard Access: HTTP 200 OK")

    # 3. Employee Login & Dashboard Rejection Check
    res_emp_login = client.post("/auth/login", json={"username_or_email": "employee@zaalima.in", "password": "Employee@123"})
    assert res_emp_login.status_code == 200, f"Employee login failed: {res_emp_login.text}"
    emp_user = res_emp_login.json()["user"]
    print(f"[PASS] Employee Login OK: username={emp_user['username']}, role={emp_user['role']}")

    res_emp_dash = client.get(f"/dashboard/metrics?user_id={emp_user['username']}")
    assert res_emp_dash.status_code == 403, f"Employee role was not blocked! Code: {res_emp_dash.status_code}"
    print(f"[PASS] Employee Dashboard Access Rejection: HTTP 403 Forbidden ({res_emp_dash.json()['detail']['error']})")

    # 4. Finance User Login & Dashboard Rejection Check
    res_fin_login = client.post("/auth/login", json={"username_or_email": "finance@zaalima.in", "password": "Finance@123"})
    assert res_fin_login.status_code == 200, f"Finance login failed: {res_fin_login.text}"
    fin_user = res_fin_login.json()["user"]
    print(f"[PASS] Finance User Login OK: username={fin_user['username']}, role={fin_user['role']}")

    res_fin_dash = client.get(f"/dashboard/metrics?user_id={fin_user['username']}")
    assert res_fin_dash.status_code == 403, f"Finance user was not blocked! Code: {res_fin_dash.status_code}"
    print(f"[PASS] Finance User Dashboard Access Rejection: HTTP 403 Forbidden")

    print("\nALL ROLE & DASHBOARD ACCESS TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_all_roles_login_and_dashboard()
