import requests

headers = {"Authorization": "Bearer dev-gateway-key-llama3"}
url = "http://localhost:8001/chat"
payload = {"prompt": ""}  # Empty prompt to trigger 400 quickly instead of waiting for LLM

print("Sending 12 requests...")
for i in range(1, 13):
    resp = requests.post(url, json=payload, headers=headers)
    print(f"Request {i}: Status {resp.status_code}")
    if resp.status_code == 429:
        print(f"Headers: {resp.headers.get('Retry-After')}")
