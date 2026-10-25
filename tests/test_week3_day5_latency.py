import time
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.prompt_injection import _check_heuristic, _check_local_ml
from app.services.pii_analyzer import analyze_pii, summarize_pii
from app.services.pii_anonymizer import anonymize
from app.providers.ollama import OllamaProvider
from app.security.content_safety import check_content_safety
from app.models.log import RequestLog
from app.db import SessionLocal
import uuid
import statistics
import asyncio

def test_component_latency():
    print("\n--- COMPONENT LATENCY BENCHMARK ---")
    
    # 1. Warm up ML model
    print("Warming up ML model...")
    warmup_start = time.perf_counter()
    _check_local_ml("hello")
    warmup_time = (time.perf_counter() - warmup_start) * 1000
    print(f"Model initialization/warmup time: {warmup_time:.2f} ms")

    prompt = "What is a firewall?"
    n_iters = 10
    
    # Heuristic
    heuristic_times = []
    for _ in range(n_iters):
        t0 = time.perf_counter()
        _check_heuristic(prompt)
        heuristic_times.append((time.perf_counter() - t0) * 1000)
    
    print(f"Heuristic avg: {statistics.mean(heuristic_times):.2f} ms")
    
    # ML
    ml_times = []
    for _ in range(n_iters):
        t0 = time.perf_counter()
        _check_local_ml(prompt)
        ml_times.append((time.perf_counter() - t0) * 1000)
    
    print(f"ML avg: {statistics.mean(ml_times):.2f} ms")
    
    # PII/DLP
    pii_times = []
    for _ in range(n_iters):
        t0 = time.perf_counter()
        anonymize(prompt)
        pii_times.append((time.perf_counter() - t0) * 1000)
        
    print(f"PII/DLP avg: {statistics.mean(pii_times):.2f} ms")
    
    # Content Safety
    cs_times = []
    response_text = "A firewall is a network security device."
    for _ in range(n_iters):
        t0 = time.perf_counter()
        check_content_safety(response_text)
        cs_times.append((time.perf_counter() - t0) * 1000)
        
    print(f"Content safety avg: {statistics.mean(cs_times):.2f} ms")
    
    # Audit Logging
    db = SessionLocal()
    audit_times = []
    for _ in range(n_iters):
        t0 = time.perf_counter()
        log_entry = RequestLog(
            request_id=str(uuid.uuid4()),
            user_token="test_token",
            provider="ollama",
            model="test_model",
            prompt="test",
            status="success"
        )
        db.add(log_entry)
        db.commit()
        audit_times.append((time.perf_counter() - t0) * 1000)
    db.close()
    
    print(f"Audit logging avg: {statistics.mean(audit_times):.2f} ms")
    
def test_full_gateway_latency():
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-api-key"}
    
    # A. Normal allowed request
    # Use mock ollama so we don't benchmark ollama server
    # Wait, the prompt says "Use a safe/mocked LLM response where appropriate"
    pass

if __name__ == "__main__":
    test_component_latency()
