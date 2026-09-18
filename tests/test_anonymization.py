import pytest
from app.services.pii_anonymizer import anonymize, deanonymize

def test_no_pii():
    """Test 1 — No PII"""
    text = "Explain what cybersecurity is."
    anonymized_text, mapping = anonymize(text)
    
    assert anonymized_text == text
    assert mapping == {}

def test_person():
    """Test 2 — Person"""
    text = "My name is Rahul."
    anonymized_text, mapping = anonymize(text)
    
    assert anonymized_text == "My name is <PERSON_1>."
    assert mapping == {"<PERSON_1>": "Rahul"}

def test_repeated_pii():
    """Test 3 — Repeated PII"""
    text = "Rahul contacted Rahul."
    anonymized_text, mapping = anonymize(text)
    
    assert anonymized_text == "<PERSON_1> contacted <PERSON_1>."
    assert mapping == {"<PERSON_1>": "Rahul"}

def test_multiple_pii():
    """Test 4 — Multiple PII"""
    # Using recognizable PII entities per standard presidio config
    text = "Rahul's email is rahul@example.com and his card is 4532-1234-5678-9012."
    anonymized_text, mapping = anonymize(text)
    
    assert "<PERSON_1>" in anonymized_text
    assert "<EMAIL_ADDRESS_1>" in anonymized_text
    
    # Check that mappings contain the right info
    values = mapping.values()
    assert "Rahul" in values
    assert "rahul@example.com" in values

def test_deanonymization():
    """Test 5 — Deanonymization"""
    text = "Hello <PERSON_1>, your email is <EMAIL_ADDRESS_1>."
    mapping = {
        "<PERSON_1>": "Rahul",
        "<EMAIL_ADDRESS_1>": "rahul@example.com"
    }
    
    deanonymized_text = deanonymize(text, mapping)
    assert deanonymized_text == "Hello Rahul, your email is rahul@example.com."

def test_end_to_end():
    """Test 6 — End-to-end"""
    original_text = "Please contact Rahul at rahul@example.com about project ZAALIMA-PROJ-2024-001."
    
    # 1. Anonymize
    anonymized_text, mapping = anonymize(original_text)
    
    # Ensure it's anonymized
    assert "Rahul" not in anonymized_text
    assert "rahul@example.com" not in anonymized_text
    assert "ZAALIMA-PROJ-2024-001" not in anonymized_text
    
    # 2. Simulate LLM response containing the placeholders
    llm_response = "Sure, I will contact <PERSON_1> at <EMAIL_ADDRESS_1> about <INTERNAL_PROJECT_CODE_1>."
    
    # 3. Deanonymize
    final_response = deanonymize(llm_response, mapping)
    
    assert "Rahul" in final_response
    assert "rahul@example.com" in final_response

def test_security_no_mapping_leak():
    """Test 7 — Security"""
    # Verify that the mapping values do not leak into the anonymized string.
    text = "Secret is MySecret123"
    # Even if this isn't caught by presidio by default, testing the theory 
    # of the function's output format.
    anonymized_text, mapping = anonymize(text)
    # Actually, let's use a real recognized entity
    text_with_pii = "My credit card is 1111-2222-3333-4444."
    anonymized_text, mapping = anonymize(text_with_pii)
    
    assert "1111-2222-3333-4444" not in anonymized_text
    assert "<CREDIT_CARD_1>" in anonymized_text
    assert mapping["<CREDIT_CARD_1>"] == "1111-2222-3333-4444"
