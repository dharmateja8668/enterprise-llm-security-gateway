import requests
import json

BASE_URL = "http://127.0.0.1:8081"
API_KEY = "dev-gateway-key-llama3"

def test_auth_and_rbac():
    print("=== TESTING ZAALIMA AUTHENTICATION & RBAC SECURITY ===")

    # 1. Login as Employee
    res = requests.post(f"{BASE_URL}/auth/login", json={
        "username_or_email": "employee@zaalima.com",
        "password": "Employee@123"
    })
    print(f"\n1. POST /auth/login (Employee) -> Status {res.status_code}")
    assert res.status_code == 200, res.text
    emp_data = res.json()
    print(f"   Authenticated User: {emp_data['user']['username']}, Role: {emp_data['user']['role']}, Dept: {emp_data['user']['department']}")
    print(f"   Allowed Models: {emp_data['allowed_models']}")
    assert emp_data['user']['role'] == "employee"

    # 2. Employee Direct Access Attempt to SOC Dashboard -> MUST RETURN 403 FORBIDDEN
    res = requests.get(f"{BASE_URL}/dashboard/metrics?user_id=employee_user")
    print(f"\n2. GET /dashboard/metrics (Employee Direct Access) -> Status {res.status_code}")
    print(f"   Response Payload: {res.json()}")
    assert res.status_code == 403
    assert "restricted to Administrators" in res.json()['detail']['error']

    # 3. Login as Administrator
    res = requests.post(f"{BASE_URL}/auth/login", json={
        "username_or_email": "admin@zaalima.com",
        "password": "Admin@123"
    })
    print(f"\n3. POST /auth/login (Administrator) -> Status {res.status_code}")
    assert res.status_code == 200, res.text
    admin_data = res.json()
    print(f"   Authenticated User: {admin_data['user']['username']}, Role: {admin_data['user']['role']}")
    assert admin_data['user']['role'] == "admin"

    # 4. Administrator Direct Access to SOC Dashboard -> 200 OK
    res = requests.get(f"{BASE_URL}/dashboard/metrics?user_id=admin_user")
    print(f"\n4. GET /dashboard/metrics (Administrator Access) -> Status {res.status_code}")
    assert res.status_code == 200
    print(f"   Metrics: Total Requests = {res.json().get('total_requests')}")

    # 5. Invalid Credentials Login -> 401 Unauthorized
    res = requests.post(f"{BASE_URL}/auth/login", json={
        "username_or_email": "employee@zaalima.com",
        "password": "WrongPassword123"
    })
    print(f"\n5. POST /auth/login (Bad Password) -> Status {res.status_code}")
    assert res.status_code == 401
    print(f"   Error Detail: {res.json()['detail']}")

    print("\n✅ ALL AUTHENTICATION & RBAC DIRECT SECURITY TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_auth_and_rbac()
