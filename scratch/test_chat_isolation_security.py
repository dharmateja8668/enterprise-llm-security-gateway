import requests
import json

BASE_URL = "http://127.0.0.1:8081"
API_KEY = "dev-gateway-key-llama3"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def test_chat_isolation():
    print("=== TESTING USER CHAT SESSION ISOLATION & ACCESS CONTROL ===")

    # 1. Login as Employee A (employee_user)
    print("\n1. Logging in as Employee A (employee_user)...")
    res = requests.post(f"{BASE_URL}/auth/login", json={"username_or_email": "employee@zaalima.com", "password": "Employee@123"})
    assert res.status_code == 200, res.text
    emp_a = res.json()["user"]["username"]

    # Create private chat for Employee A
    res = requests.post(f"{BASE_URL}/chats?user_id={emp_a}", json={"title": "Employee A Private Chat"}, headers=HEADERS)
    assert res.status_code == 200, res.text
    chat_a_id = res.json()["id"]
    print(f"   Created Employee A Chat: ID={chat_a_id}, Title='{res.json()['title']}'")

    # Send message in Employee A's chat
    res = requests.post(f"{BASE_URL}/chat", json={"prompt": "Confidential Employee A project notes", "user_id": emp_a, "chat_id": chat_a_id}, headers=HEADERS)
    assert res.status_code == 200, res.text
    print(f"   Sent message in Employee A Chat -> Status 200")

    # 2. Login as Employee B (finance_user)
    print("\n2. Logging in as Employee B (finance_user)...")
    res = requests.post(f"{BASE_URL}/auth/login", json={"username_or_email": "finance@zaalima.com", "password": "Finance@123"})
    assert res.status_code == 200, res.text
    emp_b = res.json()["user"]["username"]

    # Fetch Employee B's chat list
    res = requests.get(f"{BASE_URL}/chats?user_id={emp_b}", headers=HEADERS)
    assert res.status_code == 200, res.text
    emp_b_chats = res.json()
    emp_b_chat_ids = [c["id"] for c in emp_b_chats]
    print(f"   Employee B Chat List Count: {len(emp_b_chats)}")
    assert chat_a_id not in emp_b_chat_ids, "SECURITY FAILURE: Employee B can see Employee A's chat in list!"
    print("   [PASSED] Employee A's private chat is NOT visible to Employee B.")

    # Create private chat for Employee B
    res = requests.post(f"{BASE_URL}/chats?user_id={emp_b}", json={"title": "Employee B Private Financials"}, headers=HEADERS)
    assert res.status_code == 200, res.text
    chat_b_id = res.json()["id"]
    print(f"   Created Employee B Chat: ID={chat_b_id}, Title='{res.json()['title']}'")

    # 3. Direct Unauthorized Access Test: Employee B attempts to fetch Employee A's chat ID
    print("\n3. Testing Direct Unauthorized Access by Employee B to Employee A's Chat ID...")
    res = requests.get(f"{BASE_URL}/chats/{chat_a_id}?user_id={emp_b}", headers=HEADERS)
    print(f"   GET /chats/{chat_a_id} as Employee B -> Status {res.status_code}")
    assert res.status_code == 403, f"Expected 403 Forbidden but got {res.status_code}"
    print(f"   [PASSED] Direct read blocked with 403 Forbidden: {res.json()['detail']}")

    # Direct Unauthorized Write Test: Employee B attempts to post message to Employee A's chat ID
    res = requests.post(f"{BASE_URL}/chat", json={"prompt": "Malicious injection attempt by Employee B", "user_id": emp_b, "chat_id": chat_a_id}, headers=HEADERS)
    print(f"   POST /chat into Employee A's chat as Employee B -> Status {res.status_code}")
    assert res.status_code == 403, f"Expected 403 Forbidden but got {res.status_code}"
    print(f"   [PASSED] Direct message insertion blocked with 403 Forbidden: {res.json()['detail']}")

    # 4. Relogin as Employee A & Verify Isolation
    print("\n4. Relogging in as Employee A to verify chat state persistence...")
    res = requests.get(f"{BASE_URL}/chats?user_id={emp_a}", headers=HEADERS)
    assert res.status_code == 200, res.text
    emp_a_chats = res.json()
    emp_a_chat_ids = [c["id"] for c in emp_a_chats]
    assert chat_a_id in emp_a_chat_ids, "Employee A's chat should be present"
    assert chat_b_id not in emp_a_chat_ids, "Employee B's chat should NOT be visible to Employee A"
    print("   [PASSED] Employee A sees ONLY Employee A's chats.")

    print("\nALL CHAT ISOLATION & AUTHORIZATION TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_chat_isolation()
