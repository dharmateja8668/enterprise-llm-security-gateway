"""
tests/test_anonymization.py
Comprehensive tests for PII Anonymization & Deanonymization Service (Week 2, Day 4–6).

Covers:
 1. No PII
 2. Single PERSON
 3. Single EMAIL
 4. Credit card
 5. SSN
 6. Internal project code
 7. Multiple PII
 8. Repeated same PII
 9. Different PII values
10. PII inside punctuation
11. PII inside multiline text
12. Placeholder collision
13. Standard placeholder deanonymization
14. Supported alternate placeholder format
15. Unknown placeholder
16. Malformed placeholder
17. LLM omits placeholder
18. LLM returns multiple placeholders
19. LLM-facing prompt contains no raw PII
20. Raw PII is not unnecessarily logged
21. End-to-end /chat anonymization
22. End-to-end /chat deanonymization
23. LLM/provider failure
24. Presidio failure
25. Empty response

NOTE: All test data uses safe, synthetic, fictitious values only.
"""

import json
import logging
from unittest.mock import patch
import pytest
import respx
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.pii_anonymizer import anonymize, deanonymize
from app.models.log import RequestLog
from tests.conftest import TestingSessionLocal

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer test-token"}


def _ollama_response(content: str, model: str = "tinyllama") -> dict:
    return {
        "model": model,
        "created_at": "2024-01-01T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": True,
    }


# ==============================================================================
# 1. Service-level Anonymization Tests
# ==============================================================================

def test_01_no_pii():
    """Test 1 — Text with no PII remains unaltered with empty mapping."""
    text = "Explain the difference between symmetric and asymmetric cryptography."
    anonymized, mapping = anonymize(text)
    assert anonymized == text
    assert mapping == {}


def test_02_single_person():
    """Test 2 — Single PERSON is replaced by <PII_PERSON_1>."""
    text = "Hello, my name is Rahul."
    anonymized, mapping = anonymize(text)
    assert "<PII_PERSON_1>" in anonymized
    assert "Rahul" not in anonymized
    assert mapping.get("<PII_PERSON_1>") == "Rahul"


def test_03_single_email():
    """Test 3 — Single EMAIL_ADDRESS is replaced by <PII_EMAIL_ADDRESS_1>."""
    text = "You can reach me at rahul.test@example.com anytime."
    anonymized, mapping = anonymize(text)
    assert "<PII_EMAIL_ADDRESS_1>" in anonymized
    assert "rahul.test@example.com" not in anonymized
    assert mapping.get("<PII_EMAIL_ADDRESS_1>") == "rahul.test@example.com"


def test_04_credit_card():
    """Test 4 — CREDIT_CARD (valid test Visa) is replaced by <PII_CREDIT_CARD_1>."""
    text = "Please charge synthetic card 4111111111111111 for the purchase."
    anonymized, mapping = anonymize(text)
    assert "<PII_CREDIT_CARD_1>" in anonymized
    assert "4111111111111111" not in anonymized
    assert mapping.get("<PII_CREDIT_CARD_1>") == "4111111111111111"


def test_05_ssn():
    """Test 5 — SSN (US_SSN normalized to SSN) is replaced by <PII_SSN_1>."""
    text = "Applicant SSN is 456-78-1234 for identity verification."
    anonymized, mapping = anonymize(text)
    assert "<PII_SSN_1>" in anonymized
    assert "456-78-1234" not in anonymized
    assert mapping.get("<PII_SSN_1>") == "456-78-1234"


def test_06_internal_project_code():
    """Test 6 — INTERNAL_PROJECT_CODE is replaced by <PII_INTERNAL_PROJECT_CODE_1>."""
    text = "Assign this review to ZAALIMA-PROJ-2024-001 immediately."
    anonymized, mapping = anonymize(text)
    assert "<PII_INTERNAL_PROJECT_CODE_1>" in anonymized
    assert "ZAALIMA-PROJ-2024-001" not in anonymized
    assert mapping.get("<PII_INTERNAL_PROJECT_CODE_1>") == "ZAALIMA-PROJ-2024-001"


def test_07_multiple_pii():
    """Test 7 — Multiple different PII types in one text each receive dedicated placeholders."""
    text = (
        "Lead Rahul (email: rahul.test@example.com) submitted project "
        "ZAALIMA-PROJ-2024-002 with card 4111111111111111 and SSN 456-78-1234."
    )
    anonymized, mapping = anonymize(text)
    assert "<PII_PERSON_1>" in anonymized
    assert "<PII_EMAIL_ADDRESS_1>" in anonymized
    assert "<PII_INTERNAL_PROJECT_CODE_1>" in anonymized
    assert "<PII_CREDIT_CARD_1>" in anonymized
    assert "<PII_SSN_1>" in anonymized

    assert "Rahul" not in anonymized
    assert "rahul.test@example.com" not in anonymized
    assert "ZAALIMA-PROJ-2024-002" not in anonymized
    assert "4111111111111111" not in anonymized
    assert "456-78-1234" not in anonymized


def test_08_repeated_same_pii():
    """Test 8 — Repeated occurrences of the exact same PII entity receive the same placeholder."""
    text = "Rahul contacted Rahul. Rahul needs an urgent meeting."
    anonymized, mapping = anonymize(text)
    assert anonymized == "<PII_PERSON_1> contacted <PII_PERSON_1>. <PII_PERSON_1> needs an urgent meeting."
    assert len(mapping) == 1
    assert mapping["<PII_PERSON_1>"] == "Rahul"


def test_09_different_pii_values():
    """Test 9 — Distinct values of the same entity type receive sequential distinct placeholders."""
    text = "Alice Smith scheduled an interview with Bob Johnson."
    anonymized, mapping = anonymize(text)
    assert "<PII_PERSON_1>" in anonymized
    assert "<PII_PERSON_2>" in anonymized
    assert mapping["<PII_PERSON_1>"] != mapping["<PII_PERSON_2>"]
    assert "Alice Smith" not in anonymized
    assert "Bob Johnson" not in anonymized


def test_10_pii_inside_punctuation():
    """Test 10 — PII within quotes, parentheses, and brackets preserves exact formatting."""
    text = 'User said: ("Rahul") and ["rahul.test@example.com"].'
    anonymized, mapping = anonymize(text)
    assert '("<PII_PERSON_1>")' in anonymized
    assert '["<PII_EMAIL_ADDRESS_1>"]' in anonymized


def test_11_pii_inside_multiline_text():
    """Test 11 — PII in multiline text preserves line breaks and structure."""
    text = (
        "Summary Report:\n"
        "Candidate name is Rahul.\n"
        "Primary contact email is rahul.test@example.com.\n"
        "Project reference is ZAALIMA-PROJ-2024-001.\n"
        "End of report."
    )
    anonymized, mapping = anonymize(text)
    assert "Candidate name is <PII_PERSON_1>.\n" in anonymized
    assert "Primary contact email is <PII_EMAIL_ADDRESS_1>.\n" in anonymized
    assert "Project reference is <PII_INTERNAL_PROJECT_CODE_1>.\n" in anonymized
    assert "Rahul" not in anonymized
    assert "rahul.test@example.com" not in anonymized
    assert "ZAALIMA-PROJ-2024-001" not in anonymized
    assert anonymized.count("\n") == text.count("\n")


def test_12_placeholder_collision():
    """Test 12 — Input already containing text resembling placeholders does not collide or overwrite."""
    text = "My documentation contains <PII_PERSON_1>. My colleague is Rahul."
    anonymized, mapping = anonymize(text)

    # Rahul must NOT receive <PII_PERSON_1> because it was already present in user text
    assert "<PII_PERSON_2>" in anonymized
    assert mapping.get("<PII_PERSON_2>") == "Rahul"
    assert "<PII_PERSON_1>" not in mapping

    # When deanonymizing a response that contains both, only Rahul's placeholder is restored
    llm_simulated_response = "Reference <PII_PERSON_1> and greet <PII_PERSON_2>."
    restored = deanonymize(llm_simulated_response, mapping)
    assert restored == "Reference <PII_PERSON_1> and greet Rahul."


# ==============================================================================
# 2. Deanonymization Service Tests
# ==============================================================================

def test_13_standard_placeholder_deanonymization():
    """Test 13 — Standard <PII_...> placeholders are correctly restored."""
    response = "Hello <PII_PERSON_1>, your email is <PII_EMAIL_ADDRESS_1>."
    mapping = {
        "<PII_PERSON_1>": "Rahul",
        "<PII_EMAIL_ADDRESS_1>": "rahul.test@example.com",
    }
    restored = deanonymize(response, mapping)
    assert restored == "Hello Rahul, your email is rahul.test@example.com."


def test_14_supported_alternate_placeholder_format():
    """Test 14 — LLM returning square brackets or bare tokens is safely deanonymized."""
    mapping = {
        "<PII_PERSON_1>": "Rahul",
        "<PII_EMAIL_ADDRESS_1>": "rahul.test@example.com",
    }
    # Square brackets
    resp_brackets = "Hello [PII_PERSON_1], contact [PII_EMAIL_ADDRESS_1]."
    assert deanonymize(resp_brackets, mapping) == "Hello Rahul, contact rahul.test@example.com."

    # Bare token with word boundary
    resp_bare = "Hello PII_PERSON_1, contact PII_EMAIL_ADDRESS_1."
    assert deanonymize(resp_bare, mapping) == "Hello Rahul, contact rahul.test@example.com."

    # Case-insensitive variant
    resp_case = "Hello <pii_person_1> and [Pii_Email_Address_1]."
    assert deanonymize(resp_case, mapping) == "Hello Rahul and rahul.test@example.com."


def test_15_unknown_placeholder():
    """Test 15 — Placeholders not present in this request's mapping are left untouched."""
    response = "Hello <PII_PERSON_99>, we noticed <PII_EMAIL_ADDRESS_42>."
    mapping = {"<PII_PERSON_1>": "Rahul"}
    restored = deanonymize(response, mapping)
    assert restored == response


def test_16_malformed_placeholder():
    """Test 16 — Partial or malformed placeholders fail closed and remain unchanged."""
    response = "Hello <PII_PERSON_1 and PII_PERSON_1> and <PII_PERSON_."
    mapping = {"<PII_PERSON_1>": "Rahul"}
    restored = deanonymize(response, mapping)
    # Unbalanced brackets are excluded and fail closed
    assert restored == "Hello <PII_PERSON_1 and PII_PERSON_1> and <PII_PERSON_."
    assert "Rahul" not in restored


def test_17_llm_omits_placeholder():
    """Test 17 — When LLM completely omits placeholders, gateway does not guess or inject PII."""
    response = "Welcome to our customer service portal. How may I assist you today?"
    mapping = {"<PII_PERSON_1>": "Rahul", "<PII_EMAIL_ADDRESS_1>": "rahul.test@example.com"}
    restored = deanonymize(response, mapping)
    assert restored == response
    assert "Rahul" not in restored


def test_18_llm_returns_multiple_placeholders():
    """Test 18 — Multiple occurrences of the same placeholder and different placeholders restore consistently."""
    response = (
        "Dear <PII_PERSON_1>, thank you. <PII_PERSON_1>, please confirm <PII_EMAIL_ADDRESS_1>."
    )
    mapping = {
        "<PII_PERSON_1>": "Rahul",
        "<PII_EMAIL_ADDRESS_1>": "rahul.test@example.com",
    }
    restored = deanonymize(response, mapping)
    assert restored == "Dear Rahul, thank you. Rahul, please confirm rahul.test@example.com."


# ==============================================================================
# 3. Security, Logging & Route Integration Tests
# ==============================================================================

@respx.mock
def test_19_llm_facing_prompt_contains_no_raw_pii():
    """Test 19 — Provider call verification: outgoing prompt to LLM never contains raw PII."""
    captured_payload = {}

    def capture_request(request):
        captured_payload["body"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response("Received your inquiry, <PII_PERSON_1>."),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture_request)

    prompt_with_pii = (
        "My name is Rahul Kumar and my personal email is rahul.test@example.com. "
        "Please assist me."
    )
    resp = client.post("/chat", json={"prompt": prompt_with_pii}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_content = captured_payload["body"]["messages"][0]["content"]
    assert "Rahul" not in sent_content
    assert "rahul.test@example.com" not in sent_content
    assert "<PII_PERSON_1>" in sent_content
    assert "<PII_EMAIL_ADDRESS_1>" in sent_content


def test_20_raw_pii_not_unnecessarily_logged(caplog):
    """Test 20 — Application and security logs never output raw PII or mapping dictionaries."""
    with caplog.at_level(logging.INFO, logger="app"):
        text = "Confidential applicant Rahul with email rahul.test@example.com."
        anonymized, mapping = anonymize(text)
        _ = deanonymize("<PII_PERSON_1>", mapping)

    app_messages = " ".join(r.message for r in caplog.records if r.name.startswith("app"))
    assert "Rahul" not in app_messages
    assert "rahul.test@example.com" not in app_messages
    assert "mapping" not in app_messages.lower()


@respx.mock
def test_21_e2e_chat_anonymization():
    """Test 21 — Full /chat flow verifies prompt is anonymized in DB RequestLog and LLM."""
    captured_prompt = None

    def capture_request(request):
        nonlocal captured_prompt
        body = json.loads(request.content.decode())
        captured_prompt = body["messages"][0]["content"]
        return httpx.Response(200, json=_ollama_response("Hello from LLM"))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture_request)

    resp = client.post(
        "/chat",
        json={"prompt": "My credit card is 4111111111111111."},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 200
    assert "<PII_CREDIT_CARD_1>" in captured_prompt
    assert "4111111111111111" not in captured_prompt

    # Verify PostgreSQL RequestLog stores safe_prompt
    db = TestingSessionLocal()
    try:
        log_entry = db.query(RequestLog).filter(RequestLog.prompt == "My credit card is <PII_CREDIT_CARD_1>.").first()
        assert log_entry is not None
        assert "<PII_CREDIT_CARD_1>" in log_entry.prompt
        assert "4111111111111111" not in log_entry.prompt
    finally:
        db.close()


@respx.mock
def test_22_e2e_chat_deanonymization():
    """Test 22 — Full /chat flow verifies LLM placeholder response is restored in final API response."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json=_ollama_response("Welcome <PII_PERSON_1>! We sent details to <PII_EMAIL_ADDRESS_1>."),
        )
    )

    resp = client.post(
        "/chat",
        json={"prompt": "I am Rahul and email is rahul.test@example.com."},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    # Returned to user with original values restored
    assert data["response"] == "Welcome Rahul! We sent details to rahul.test@example.com."
    assert data["pii_summary"]["pii_detected"] is True


@respx.mock
def test_23_llm_provider_failure():
    """Test 23 — Provider error returns proper 503 HTTP status and logs failure cleanly."""
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    resp = client.post(
        "/chat",
        json={"prompt": "Hello Rahul."},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 503
    db = TestingSessionLocal()
    try:
        log_entry = db.query(RequestLog).filter(RequestLog.prompt == "Hello <PII_PERSON_1>.").first()
        assert log_entry is not None
        assert log_entry.status == "error"
    finally:
        db.close()


def test_24_presidio_failure():
    """Test 24 — Presidio analyzer failure causes endpoint to fail closed without sending prompt to LLM."""
    with patch("app.routes.basic_chat.analyze_pii", side_effect=RuntimeError("Presidio engine crash")):
        resp = client.post(
            "/chat",
            json={"prompt": "My name is Rahul."},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 500
        assert "Security scanning failed" in resp.json()["detail"]


@respx.mock
def test_25_empty_response():
    """Test 25 — Empty LLM response handled safely at both service and API levels."""
    # Service level: empty response deanonymizes cleanly
    mapping = {"<PII_PERSON_1>": "Rahul"}
    assert deanonymize("", mapping) == ""
    assert deanonymize(None, mapping) is None

    # Endpoint level: OllamaProvider raises 500 when empty response returned
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json=_ollama_response(""))
    )

    resp = client.post(
        "/chat",
        json={"prompt": "Tell me nothing."},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 500
    assert "empty response" in resp.json()["detail"].lower()


def test_26_concurrent_anonymization_requests():
    """Test 26 — Verify that concurrent requests do not cross-contaminate mappings or placeholders."""
    from concurrent.futures import ThreadPoolExecutor

    test_cases = [
        ("User Alice with email alice@example.com and SSN 111-22-3333", "Alice", "alice@example.com"),
        ("User Bob with email bob@example.com and SSN 222-33-4444", "Bob", "bob@example.com"),
        ("User Charlie with email charlie@example.com and SSN 333-44-5555", "Charlie", "charlie@example.com"),
        ("User David with email david@example.com and SSN 444-55-6666", "David", "david@example.com"),
        ("User Eve with email eve@example.com and SSN 555-66-7777", "Eve", "eve@example.com"),
    ]

    def process_case(case):
        raw_text, expected_name, expected_email = case
        anon, mapping = anonymize(raw_text)
        assert expected_name not in anon
        assert expected_email not in anon
        # Verify placeholders match this thread's entities exclusively
        restored = deanonymize(anon, mapping)
        assert restored == raw_text
        return True

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(process_case, test_cases))

    assert all(results)
    assert len(results) == 5
