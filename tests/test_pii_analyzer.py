"""
tests/test_pii_analyzer.py
Comprehensive tests for the Presidio PII detection service (Week 2, Day 1).

Tests cover:
  - Individual PII entity detection (names, emails, phone, credit cards, SSNs)
  - Multiple PII in a single text
  - Clean text with no PII
  - Score threshold filtering
  - Convenience helpers (contains_pii, summarize_pii)
  - The /pii/scan REST endpoint
  - PII detection integration in the /chat endpoint

IMPORTANT: All test data uses safe, fictitious values only.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.pii_analyzer import (
    analyze_pii,
    contains_pii,
    summarize_pii,
    reset_analyzer,
)

client = TestClient(app)


# ───────────────────────────────────────────────────────────────────────────
# Unit tests — analyze_pii() service function
# ───────────────────────────────────────────────────────────────────────────


class TestNameDetection:
    """Detect PERSON entities."""

    def test_detect_name(self):
        entities = analyze_pii("My name is Rahul Kumar.")
        types = [e.entity_type for e in entities]
        assert "PERSON" in types
        person = next(e for e in entities if e.entity_type == "PERSON")
        assert person.text_snippet == "Rahul Kumar"
        assert person.score > 0


class TestEmailDetection:
    """Detect EMAIL_ADDRESS entities."""

    def test_detect_email(self):
        entities = analyze_pii("My email is rahul@example.com.")
        types = [e.entity_type for e in entities]
        assert "EMAIL_ADDRESS" in types
        email = next(e for e in entities if e.entity_type == "EMAIL_ADDRESS")
        assert "rahul@example.com" in email.text_snippet


class TestCreditCardDetection:
    """Detect CREDIT_CARD entities."""

    def test_detect_credit_card(self):
        entities = analyze_pii("My credit card number is 4111111111111111.")
        types = [e.entity_type for e in entities]
        assert "CREDIT_CARD" in types
        cc = next(e for e in entities if e.entity_type == "CREDIT_CARD")
        assert "4111111111111111" in cc.text_snippet


class TestSSNDetection:
    """Detect US_SSN entities."""

    def test_detect_ssn(self):
        entities = analyze_pii("My SSN is 456-78-1234.")
        types = [e.entity_type for e in entities]
        assert "US_SSN" in types
        ssn = next(e for e in entities if e.entity_type == "US_SSN")
        assert "456-78-1234" in ssn.text_snippet


class TestPhoneDetection:
    """Detect PHONE_NUMBER entities."""

    def test_detect_phone(self):
        entities = analyze_pii("Call me at 212-555-0198.")
        types = [e.entity_type for e in entities]
        assert "PHONE_NUMBER" in types


class TestInternalProjectCodeDetection:
    """Detect INTERNAL_PROJECT_CODE entities."""

    def test_detect_project_code(self):
        entities = analyze_pii("Please bill this to ZAALIMA-PROJ-2026-001.")
        types = [e.entity_type for e in entities]
        assert "INTERNAL_PROJECT_CODE" in types
        proj = next(e for e in entities if e.entity_type == "INTERNAL_PROJECT_CODE")
        assert "ZAALIMA-PROJ-2026-001" in proj.text_snippet


class TestMultiplePII:
    """Detect multiple PII types in a single text."""

    def test_multiple_pii_in_one_text(self):
        text = (
            "My name is Rahul Kumar, "
            "my email is rahul@example.com, "
            "and my credit card is 4111111111111111."
        )
        entities = analyze_pii(text)
        types = {e.entity_type for e in entities}
        assert "PERSON" in types
        assert "EMAIL_ADDRESS" in types
        assert "CREDIT_CARD" in types
        assert len(entities) >= 3


class TestCleanText:
    """No PII should be detected in generic text."""

    def test_clean_text(self):
        entities = analyze_pii("The weather is nice today.")
        assert len(entities) == 0

    def test_technical_text(self):
        entities = analyze_pii(
            "SELECT * FROM users WHERE active = true ORDER BY id;"
        )
        # May return 0 or very-low-confidence hits; either is acceptable
        high_confidence = [e for e in entities if e.score >= 0.5]
        assert len(high_confidence) == 0


class TestScoreThreshold:
    """Verify the score_threshold parameter filters results."""

    def test_high_threshold_filters_low_scores(self):
        text = "My name is Rahul Kumar and my email is rahul@example.com."
        all_entities = analyze_pii(text, score_threshold=0.0)
        high_entities = analyze_pii(text, score_threshold=0.9)
        # High threshold should return fewer or equal entities
        assert len(high_entities) <= len(all_entities)


class TestEntityPositions:
    """Ensure start/end positions and text_snippet are consistent."""

    def test_positions_match_snippet(self):
        text = "My credit card is 4111111111111111."
        entities = analyze_pii(text)
        for entity in entities:
            assert entity.text_snippet == text[entity.start : entity.end]
            assert entity.start < entity.end

    def test_entities_sorted_by_start(self):
        text = "Email rahul@example.com, card 4111111111111111."
        entities = analyze_pii(text)
        starts = [e.start for e in entities]
        assert starts == sorted(starts)


class TestConvenienceHelpers:
    """Tests for contains_pii() and summarize_pii()."""

    def test_contains_pii_true(self):
        assert contains_pii("My SSN is 456-78-1234.") is True

    def test_contains_pii_false(self):
        assert contains_pii("The weather is sunny.") is False

    def test_summarize_pii_with_entities(self):
        entities = analyze_pii("My email is rahul@example.com.")
        summary = summarize_pii(entities)
        assert summary["pii_detected"] is True
        assert summary["count"] >= 1
        assert "EMAIL_ADDRESS" in summary["entity_types"]

    def test_summarize_pii_empty(self):
        summary = summarize_pii([])
        assert summary["pii_detected"] is False
        assert summary["count"] == 0
        assert summary["entity_types"] == []


class TestToDict:
    """Ensure PIIEntity.to_dict() works for JSON serialization."""

    def test_to_dict(self):
        entities = analyze_pii("My email is rahul@example.com.")
        assert len(entities) >= 1
        d = entities[0].to_dict()
        assert isinstance(d, dict)
        assert "entity_type" in d
        assert "start" in d
        assert "end" in d
        assert "score" in d
        assert "text_snippet" in d


# ───────────────────────────────────────────────────────────────────────────
# Integration tests — /pii/scan endpoint
# ───────────────────────────────────────────────────────────────────────────


class TestPIIScanEndpoint:
    """Tests for POST /pii/scan."""

    def test_scan_detects_email(self):
        resp = client.post("/pii/scan", json={"text": "Email rahul@example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_detected"] is True
        assert "EMAIL_ADDRESS" in data["entity_types"]
        assert data["count"] >= 1
        assert len(data["findings"]) >= 1

    def test_scan_detects_credit_card(self):
        resp = client.post(
            "/pii/scan",
            json={"text": "My credit card is 4111111111111111."},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_detected"] is True
        assert "CREDIT_CARD" in data["entity_types"]

    def test_scan_detects_ssn(self):
        resp = client.post(
            "/pii/scan", json={"text": "My SSN is 456-78-1234."}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_detected"] is True
        assert "US_SSN" in data["entity_types"]

    def test_scan_clean_text(self):
        resp = client.post(
            "/pii/scan",
            json={"text": "The sky is blue and the grass is green."},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_detected"] is False
        assert data["count"] == 0
        assert data["findings"] == []

    def test_scan_with_threshold(self):
        resp = client.post(
            "/pii/scan",
            json={
                "text": "Contact rahul@example.com or call 212-555-0198.",
                "score_threshold": 0.8,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # All returned findings should meet the threshold
        for finding in data["findings"]:
            assert finding["score"] >= 0.8

    def test_scan_no_text_returns_422(self):
        resp = client.post("/pii/scan", json={})
        assert resp.status_code == 422

    def test_scan_multiple_pii(self):
        resp = client.post(
            "/pii/scan",
            json={
                "text": (
                    "My name is Rahul Kumar, "
                    "email rahul@example.com, "
                    "SSN 456-78-1234, "
                    "card 4111111111111111, "
                    "project ZAALIMA-PROJ-2026-001."
                )
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_detected"] is True
        assert data["count"] >= 5
        found_types = set(data["entity_types"])
        assert {"PERSON", "EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD", "INTERNAL_PROJECT_CODE"}.issubset(
            found_types
        )


# ───────────────────────────────────────────────────────────────────────────
# Integration test — PII detection in /chat endpoint
# ───────────────────────────────────────────────────────────────────────────


class TestChatPIIIntegration:
    """Verify that PII detection runs in the /chat flow without breaking it."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """This uses the autouse fixtures from conftest.py."""
        pass

    def test_chat_returns_pii_summary_when_pii_present(self):
        """When PII is in the prompt, the response includes pii_summary."""
        import respx
        import httpx

        with respx.mock:
            respx.post("http://localhost:11434/api/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "model": "tinyllama",
                        "message": {"role": "assistant", "content": "Hello!"},
                        "done": True,
                    },
                )
            )

            resp = client.post(
                "/chat",
                json={"prompt": "My name is Rahul Kumar."},
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        # PII summary should be present
        assert "pii_summary" in data
        assert data["pii_summary"]["pii_detected"] is True
        assert "PERSON" in data["pii_summary"]["entity_types"]

    def test_chat_returns_pii_summary_when_no_pii(self):
        """When no PII is in the prompt, pii_summary shows nothing detected."""
        import respx
        import httpx

        with respx.mock:
            respx.post("http://localhost:11434/api/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "model": "tinyllama",
                        "message": {"role": "assistant", "content": "Weather report."},
                        "done": True,
                    },
                )
            )

            resp = client.post(
                "/chat",
                json={"prompt": "What is the weather today?"},
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["pii_summary"]["pii_detected"] is False
        assert data["pii_summary"]["count"] == 0

    def test_chat_does_not_redact_prompt(self):
        """Day 1: PII is detected but the original prompt is NOT modified."""
        import respx
        import httpx

        captured_body = {}

        def capture_request(request):
            import json
            captured_body["prompt"] = json.loads(request.content.decode())["messages"][0]["content"]
            return httpx.Response(
                200,
                json={
                    "model": "tinyllama",
                    "message": {"role": "assistant", "content": "OK"},
                    "done": True,
                },
            )

        with respx.mock:
            respx.post("http://localhost:11434/api/chat").mock(
                side_effect=capture_request
            )

            original_prompt = "My email is rahul@example.com."
            resp = client.post(
                "/chat",
                json={"prompt": original_prompt},
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 200
        # The prompt sent to Ollama must still contain the original PII
        assert captured_body["prompt"] == original_prompt
