import pytest
from app.services.pii_analyzer import analyze_pii
from app.services.pii_anonymizer import anonymize

class TestA_SensitiveDataDetection:
    """A. Sensitive data detection"""

    def test_detect_credit_card(self):
        text = "My CC is 4111111111111111"
        entities = analyze_pii(text)
        types = [e.entity_type for e in entities]
        assert "CREDIT_CARD" in types

    def test_detect_ssn(self):
        text = "My SSN is 123-45-6789"
        entities = analyze_pii(text)
        types = [e.entity_type for e in entities]
        assert "US_SSN" in types

    def test_detect_name(self):
        text = "My name is John Doe"
        entities = analyze_pii(text)
        types = [e.entity_type for e in entities]
        assert "PERSON" in types

    def test_detect_project_code(self):
        text = "Code is ZAALIMA-PROJ-2026-001"
        entities = analyze_pii(text)
        types = [e.entity_type for e in entities]
        assert "INTERNAL_PROJECT_CODE" in types


class TestB_FormatVariations:
    """B. Format variations"""

    def test_cc_with_spaces_and_hyphens(self):
        texts = [
            "4111 1111 1111 1111",
            "4111-1111-1111-1111"
        ]
        for t in texts:
            entities = analyze_pii(t)
            assert "CREDIT_CARD" in [e.entity_type for e in entities], f"Failed for {t}"

    def test_project_code_different_capitalization(self):
        text = "Project zaalima-proj-2026-001"
        entities = analyze_pii(text)
        assert "INTERNAL_PROJECT_CODE" in [e.entity_type for e in entities]

    def test_ssn_with_spaces(self):
        text = "SSN is 123 45 6789"
        entities = analyze_pii(text)
        assert "US_SSN" in [e.entity_type for e in entities]


class TestC_BypassTesting:
    """C. Bypass testing"""

    def test_cc_embedded_in_text(self):
        text = "MyID4111111111111111isHere"
        # Often Presidio misses numbers embedded in text without spaces.
        # We will check if it detects or redacts.
        entities = analyze_pii(text)
        assert "CREDIT_CARD" in [e.entity_type for e in entities]

    def test_ssn_different_separators(self):
        text = "SSN: 123.45.6789"
        entities = analyze_pii(text)
        assert "US_SSN" in [e.entity_type for e in entities]

    def test_extra_whitespace_between_tokens(self):
        text = "ZAALIMA - PROJ - 2026 - 001"
        entities = analyze_pii(text)
        # Assuming the regex requires no spaces, this might be a bypass
        assert "INTERNAL_PROJECT_CODE" in [e.entity_type for e in entities]


class TestD_NegativeTests:
    """D. Negative tests"""

    def test_normal_text_not_redacted(self):
        text = "Hello, what is the weather today?"
        anonymized, mapping = anonymize(text)
        assert anonymized == text
        assert not mapping


class TestE_RedactionTests:
    """E. Redaction tests"""

    def test_redaction_format_and_preservation(self):
        text = "Hello, my email is test@example.com."
        anonymized, mapping = anonymize(text)
        assert "test@example.com" not in anonymized
        assert "<PII_EMAIL_ADDRESS_1>" in anonymized
        assert anonymized.startswith("Hello, my email is ")
        assert anonymized.endswith(".")


class TestF_MultiplePII:
    """F. Multiple-PII tests"""

    def test_multiple_pii_types(self):
        text = "My name is John Doe, email is john@example.com, and SSN is 123-45-6789."
        anonymized, mapping = anonymize(text)
        
        assert "John Doe" not in anonymized
        assert "john@example.com" not in anonymized
        assert "123-45-6789" not in anonymized
        
        assert "<PII_PERSON_1>" in anonymized
        assert "<PII_EMAIL_ADDRESS_1>" in anonymized
        assert "<PII_SSN_1>" in anonymized
