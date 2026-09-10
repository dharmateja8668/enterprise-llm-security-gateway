from fastapi.testclient import TestClient
from app.main import app
import json

client = TestClient(app)

def run_tests():
    print("--- Running Day 3 Tests ---\n")
    
    # 1. GET /health
    print("Test 1: GET /health")
    response = client.get("/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}\n")

    # 2. POST /chat with a valid prompt
    print("Test 2: POST /chat with valid prompt")
    response = client.post("/chat", json={"prompt": "Explain cybersecurity"})
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}\n")

    # 3. POST /chat with an empty prompt
    print("Test 3: POST /chat with empty prompt")
    response = client.post("/chat", json={"prompt": "   "})
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}\n")

    # 4. POST /chat without the prompt field
    print("Test 4: POST /chat without prompt field")
    response = client.post("/chat", json={"other_field": "test"})
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}\n")
    
if __name__ == "__main__":
    run_tests()
