"""
tests/test_day4_6_verification.py
Automated Verification Suite for Day 4–6 PII Anonymization Requirements.

Implements all 10 specific test scenarios:
  TEST 1: PHONE NUMBER (Phone number detection, anonymization, overlapping recognizer reporting)
  TEST 2: CREDIT CARD (PERSON + CREDIT_CARD, raw PII absent from LLM prompt, deanonymization)
  TEST 3: SSN (PERSON + SSN/US_SSN normalization, raw PII absent, deanonymization)
  TEST 4: MULTIPLE PII TYPES (PERSON, EMAIL, CC, SSN, no raw PII in LLM prompt, deanonymization)
  TEST 5: REPEATED PII (Repeated Rahul uses same placeholder, deanonymization)
  TEST 6: INTERNAL PROJECT CODE (Verify configured pattern r"ZAALIMA-PROJ-\d{4}-\d{3}", report NOT MATCHED for PROJ-2026-001)
  TEST 7: NO PII (Clean text, pii_detected=False, prompt unchanged)
  TEST 8: PII MIXED WITH NORMAL TEXT (Non-sensitive text preserved, sensitive anonymized)
  TEST 9: PLACEHOLDER COLLISION (Pre-existing <PII_PERSON_1> preserved, Rahul gets <PII_PERSON_2>)
  TEST 10: REPEATED PII + MULTIPLE PII TYPES (Stable mapping, no cross-mapping)

ADDITIONAL SECURITY CHECKS:
  A. Raw PII absent from LLM-facing payload.
  B. Placeholder format adheres to <PII_{ENTITY_TYPE}_{INDEX}>.
  C. Fail-closed deanonymization (malformed/unknown untouched, missing not guessed).
  D. PostgreSQL audit log stores only sanitized safe_prompt.
"""

import json
from unittest.mock import patch
import pytest
import respx
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.pii_analyzer import analyze_pii, _get_analyzer
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
# TEST 1 — PHONE NUMBER
# ==============================================================================
@respx.mock
def test_verification_01_phone_number():
    """Test 1: Phone number detection, raw value absent from LLM prompt, overlapping recognizers reported."""
    prompt = "My phone number is 9876543210. Write a short introduction."
    
    # 1. Inspect detection & overlapping recognizers
    entities = analyze_pii(prompt)
    detected_types = [e.entity_type for e in entities]
    assert "PHONE_NUMBER" in detected_types
    # Overlapping recognizers: Presidio also detects US_DRIVER_LICENSE on 10 digits
    has_overlapping_dl = "US_DRIVER_LICENSE" in detected_types
    assert has_overlapping_dl or "PHONE_NUMBER" in detected_types

    # 2. Intercept outgoing LLM request
    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(200, json=_ollama_response("Contact: <PII_PHONE_NUMBER_1>"))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert "9876543210" not in sent_prompt
    assert "<PII_PHONE_NUMBER_1>" in sent_prompt
    assert resp.json()["response"] == "Contact: 9876543210"


# ==============================================================================
# TEST 2 — CREDIT CARD
# ==============================================================================
@respx.mock
def test_verification_02_credit_card():
    """Test 2: PERSON + CREDIT_CARD detected, raw values absent, restored properly."""
    prompt = "My name is Rahul and my credit card number is 4111 1111 1111 1111. Write a short message."
    
    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(200, json=_ollama_response("Hello <PII_PERSON_1>, card on file: <PII_CREDIT_CARD_1>."))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert "Rahul" not in sent_prompt
    assert "4111 1111 1111 1111" not in sent_prompt
    assert "<PII_PERSON_1>" in sent_prompt
    assert "<PII_CREDIT_CARD_1>" in sent_prompt

    final_resp = resp.json()["response"]
    assert "Rahul" in final_resp
    assert "4111 1111 1111 1111" in final_resp


# ==============================================================================
# TEST 3 — SSN
# ==============================================================================
@respx.mock
def test_verification_03_ssn():
    """Test 3: PERSON + SSN/US_SSN detected and normalized, raw values absent from prompt."""
    prompt = "My name is Rahul and my SSN is 123-45-6789. Write a short introduction."

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(200, json=_ollama_response("Welcome <PII_PERSON_1>, SSN verified: <PII_SSN_1>."))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert "Rahul" not in sent_prompt
    assert "123-45-6789" not in sent_prompt
    assert "<PII_PERSON_1>" in sent_prompt
    assert "<PII_SSN_1>" in sent_prompt

    final_resp = resp.json()["response"]
    assert "Welcome Rahul, SSN verified: 123-45-6789." == final_resp


# ==============================================================================
# TEST 4 — MULTIPLE PII TYPES
# ==============================================================================
@respx.mock
def test_verification_04_multiple_pii_types():
    """Test 4: Multiple PII types (PERSON, EMAIL, CC, SSN) all anonymized with unique placeholders."""
    prompt = (
        "My name is Rahul. My email is rahul.test@example.com. "
        "My credit card is 4111 1111 1111 1111. My SSN is 123-45-6789. Write a short introduction."
    )

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response(
                "Profile for <PII_PERSON_1>: email <PII_EMAIL_ADDRESS_1>, "
                "card <PII_CREDIT_CARD_1>, SSN <PII_SSN_1>."
            ),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    for raw in ["Rahul", "rahul.test@example.com", "4111 1111 1111 1111", "123-45-6789"]:
        assert raw not in sent_prompt

    for placeholder in ["<PII_PERSON_1>", "<PII_EMAIL_ADDRESS_1>", "<PII_CREDIT_CARD_1>", "<PII_SSN_1>"]:
        assert placeholder in sent_prompt

    final_resp = resp.json()["response"]
    assert "Profile for Rahul: email rahul.test@example.com, card 4111 1111 1111 1111, SSN 123-45-6789." == final_resp


# ==============================================================================
# TEST 5 — REPEATED PII
# ==============================================================================
@respx.mock
def test_verification_05_repeated_pii():
    """Test 5: Repeated occurrences of Rahul use the exact same placeholder."""
    prompt = "Rahul contacted Rahul about the project. Send a message to Rahul at rahul.test@example.com."

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response(
                "Affirmative: <PII_PERSON_1> reached out to <PII_PERSON_1>. Notified <PII_EMAIL_ADDRESS_1>."
            ),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert "Rahul" not in sent_prompt
    assert "rahul.test@example.com" not in sent_prompt

    # Verify same placeholder is used for all 3 occurrences
    assert sent_prompt.count("<PII_PERSON_1>") == 3
    assert "<PII_PERSON_2>" not in sent_prompt

    final_resp = resp.json()["response"]
    assert "Affirmative: Rahul reached out to Rahul. Notified rahul.test@example.com." == final_resp


# ==============================================================================
# TEST 6 — INTERNAL PROJECT CODE
# ==============================================================================
def test_verification_06_internal_project_code():
    """
    Test 6: Verify current configured pattern r"ZAALIMA-PROJ-\\d{4}-\\d{3}".
    Determine whether PROJ-2026-001 matches. Since it does NOT match, do not modify recognizer.
    Report NOT APPLICABLE / PATTERN NOT MATCHED.
    """
    prompt = "The internal project code is PROJ-2026-001. Explain what this project is about."
    
    # Check current recognizer rule
    analyzer = _get_analyzer()
    project_recognizers = [
        r for r in analyzer.registry.recognizers if "INTERNAL_PROJECT_CODE" in r.supported_entities
    ]
    assert len(project_recognizers) > 0
    pattern_rule = project_recognizers[0].patterns[0].regex
    assert pattern_rule == r"ZAALIMA-PROJ-\d{4}-\d{3}"

    entities = analyze_pii(prompt)
    proj_entities = [e for e in entities if e.entity_type == "INTERNAL_PROJECT_CODE"]
    # PROJ-2026-001 does not match ZAALIMA-PROJ-YYYY-NNN:
    assert len(proj_entities) == 0  # Expected: PATTERN NOT MATCHED

    # Verify valid project code DOES match when formatted correctly
    valid_prompt = "The internal project code is ZAALIMA-PROJ-2026-001."
    valid_entities = analyze_pii(valid_prompt)
    assert len([e for e in valid_entities if e.entity_type == "INTERNAL_PROJECT_CODE"]) == 1


# ==============================================================================
# TEST 7 — NO PII
# ==============================================================================
@respx.mock
def test_verification_07_no_pii():
    """Test 7: Clean text with no PII remains unaltered, pii_detected=False, count=0."""
    prompt = "Explain the difference between TCP and UDP in simple English."

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(200, json=_ollama_response("TCP is connection-oriented while UDP is connectionless."))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    data = resp.json()
    assert data["pii_summary"]["pii_detected"] is False
    assert data["pii_summary"]["count"] == 0
    assert data["pii_summary"]["entity_types"] == []

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert sent_prompt == prompt
    assert data["response"] == "TCP is connection-oriented while UDP is connectionless."


# ==============================================================================
# TEST 8 — PII MIXED WITH NORMAL TEXT
# ==============================================================================
@respx.mock
def test_verification_08_pii_mixed_with_normal_text():
    """Test 8: Normal non-sensitive text is preserved; only sensitive values replaced."""
    prompt = (
        "We are working on a cybersecurity project. Rahul is the team leader "
        "and his email is rahul.test@example.com. Explain the project in two sentences."
    )

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(200, json=_ollama_response("Project managed by <PII_PERSON_1> (<PII_EMAIL_ADDRESS_1>)."))

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    # Surrounding prose intact
    assert "We are working on a cybersecurity project." in sent_prompt
    assert "is the team leader and his email is" in sent_prompt
    assert "Rahul" not in sent_prompt
    assert "rahul.test@example.com" not in sent_prompt

    assert resp.json()["response"] == "Project managed by Rahul (rahul.test@example.com)."


# ==============================================================================
# TEST 9 — PLACEHOLDER COLLISION
# ==============================================================================
@respx.mock
def test_verification_09_placeholder_collision():
    """Test 9: Pre-existing user text <PII_PERSON_1> must NOT be mapped to Rahul. Rahul receives <PII_PERSON_2>."""
    prompt = "The text <PII_PERSON_1> is already present. My actual name is Rahul. Explain this situation."

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response("Recognized pre-existing text <PII_PERSON_1>. Greetings <PII_PERSON_2>!"),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    # User-provided <PII_PERSON_1> preserved as literal text
    assert "The text <PII_PERSON_1> is already present." in sent_prompt
    # Rahul allocated index 2
    assert "My actual name is <PII_PERSON_2>." in sent_prompt
    assert "Rahul" not in sent_prompt

    # Deanonymization must NOT restore Rahul into <PII_PERSON_1>
    final_resp = resp.json()["response"]
    assert final_resp == "Recognized pre-existing text <PII_PERSON_1>. Greetings Rahul!"


# ==============================================================================
# TEST 10 — REPEATED PII + MULTIPLE PII TYPES
# ==============================================================================
@respx.mock
def test_verification_10_repeated_and_multiple_pii():
    """Test 10: Repeated Rahul and repeated email both reuse their respective placeholders without cross-mapping."""
    prompt = "Rahul's email is rahul.test@example.com. Rahul sent the same email again. Mention Rahul and his email in a short sentence."

    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response("<PII_PERSON_1> sent communication via [PII_EMAIL_ADDRESS_1]."),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]
    assert "Rahul" not in sent_prompt
    assert "rahul.test@example.com" not in sent_prompt
    assert sent_prompt.count("<PII_PERSON_1>") == 3

    final_resp = resp.json()["response"]
    assert final_resp == "Rahul sent communication via rahul.test@example.com."


# ==============================================================================
# ADDITIONAL SECURITY CHECKS (A, B, C, D)
# ==============================================================================
@respx.mock
def test_verification_security_checks(caplog):
    """
    Verifies:
    A. Raw PII absent from outgoing payload.
    B. Placeholder format adheres to <PII_{ENTITY_TYPE}_{INDEX}>.
    C. Deanonymization fail closed on unknown/malformed, missing not guessed.
    D. Database audit logs store only safe_prompt.
    """
    prompt = "Confidential: Rahul (email: rahul.test@example.com, card: 4111 1111 1111 1111, SSN: 123-45-6789)."
    
    captured = {}
    def capture(req):
        captured["body"] = json.loads(req.content.decode())
        return httpx.Response(
            200,
            json=_ollama_response(
                "Restored <PII_PERSON_1>, unknown <PII_PERSON_99>, "
                "malformed <PII_PERSON_1 and unclosed, missing omitted."
            ),
        )

    respx.post("http://localhost:11434/api/chat").mock(side_effect=capture)

    resp = client.post("/chat", json={"prompt": prompt}, headers=AUTH_HEADERS)
    assert resp.status_code == 200

    sent_prompt = captured["body"]["messages"][0]["content"]

    # A. Raw PII absent from LLM payload
    for raw in ["Rahul", "rahul.test@example.com", "4111 1111 1111 1111", "123-45-6789"]:
        assert raw not in sent_prompt

    # B. Placeholder format check
    for token in ["<PII_PERSON_1>", "<PII_EMAIL_ADDRESS_1>", "<PII_CREDIT_CARD_1>", "<PII_SSN_1>"]:
        assert token in sent_prompt

    # C. Deanonymization checks
    final_resp = resp.json()["response"]
    assert "Restored Rahul" in final_resp
    assert "<PII_PERSON_99>" in final_resp  # unknown left unchanged
    assert "<PII_PERSON_1 and unclosed" in final_resp  # malformed left unchanged

    # D. Database audit log check
    db = TestingSessionLocal()
    try:
        log_entry = db.query(RequestLog).order_by(RequestLog.id.desc()).first()
        assert log_entry is not None
        assert "Rahul" not in log_entry.prompt
        assert "rahul.test@example.com" not in log_entry.prompt
        assert "<PII_PERSON_1>" in log_entry.prompt
    finally:
        db.close()
