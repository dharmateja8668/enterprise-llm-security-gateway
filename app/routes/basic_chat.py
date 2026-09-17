"""
app/routes/basic_chat.py
POST /chat — The primary gateway chat endpoint.

Security flow (Day 1–6 + Week 2):
  1. Authentication     — verify_api_key()       → 401 if missing/invalid
  2. Rate Limiting      — check_rate_limit()     → 429 if over 10 req/min
  3. PII Detection      — analyze_pii()          → detects PII (Day 1: log only)
  4. PII/PHI Redaction  — (planned: Day 2–3)     → strips PII before LLM sees it
  5. Injection Detection— (planned: Rebuff)      → rejects malicious prompts
  6. Ollama LLM         — OllamaProvider.chat()  → real model response
  7. Content Safety     — (planned)              → screens response
  8. Audit Logging      — PostgreSQL             → records interaction
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from app.security.auth import verify_api_key
from app.security.rate_limiter import check_rate_limit
from app.providers.ollama import OllamaProvider
from app.services.pii_analyzer import analyze_pii, summarize_pii
from sqlalchemy.orm import Session
# from app.models.log import RequestLog
from app.db import get_db
import hashlib

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Chat"], dependencies=[Security(HTTPBearer(auto_error=False))])

# Lazy singleton — created on the first request so that tests that set
# OLLAMA_BASE_URL / OLLAMA_MODEL *after* import still get the correct values.
_ollama_instance: OllamaProvider | None = None


def _get_ollama() -> OllamaProvider:
    """Return the shared OllamaProvider, creating it on first call."""
    global _ollama_instance
    if _ollama_instance is None:
        _ollama_instance = OllamaProvider()
    return _ollama_instance


def _reset_ollama() -> None:
    """Reset the cached provider (used by tests to pick up new env vars)."""
    global _ollama_instance
    _ollama_instance = None


def _token_identifier(token: str) -> str:
    """Return a safe, opaque SHA-256 digest of the bearer token.

    The raw token is NEVER stored in the database.  The first 16 hex chars of
    the digest are enough to correlate audit logs to a client without exposing
    the secret.
    """
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class SimpleChatRequest(BaseModel):
    prompt: str


class PIISummary(BaseModel):
    """Summary of PII entities detected in the prompt (Week 2, Day 1)."""
    pii_detected: bool
    count: int
    entity_types: List[str]


class SimpleChatResponse(BaseModel):
    success: bool
    response: str
    model: str
    pii_summary: Optional[PIISummary] = None


@router.post("/chat", response_model=SimpleChatResponse)
async def chat_endpoint(
    request: SimpleChatRequest,
    user_token: str = Depends(verify_api_key), db: Session = Depends(get_db),
):
    """
    POST /chat — authenticated, rate-limited gateway to the internal Ollama LLM.

    Full request flow:
      User → FastAPI → Auth (Day 4) → Rate Limit (Day 5)
      → PII Detection (Week 2) → Ollama (Day 6) → User
    """
    ollama = _get_ollama()
    
    # ── Day 4: Authentication (enforced by Depends above) ──────────────────
    # verify_api_key() already ran; user_token holds the validated token.

    # ── Day 5: Rate Limiting ────────────────────────────────────────────────
    check_rate_limit(user_token)

    # ── Day 6a: Input validation ────────────────────────────────────────────
    if not request.prompt or not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    # ── Week 2 Day 1: PII Detection (detection only — no redaction yet) ────
    pii_entities = analyze_pii(request.prompt, score_threshold=0.0)
    pii_summary_data = summarize_pii(pii_entities)
    pii_summary = PIISummary(**pii_summary_data)

    if pii_summary.pii_detected:
        logger.warning(
            "PII detected in prompt: %d entit(ies), types=%s",
            pii_summary.count,
            pii_summary.entity_types,
        )

    # ── Week 2 Day 2–3 (placeholder): PII/PHI Redaction via Presidio ───────
    # safe_prompt = presidio_redact(request.prompt)   # ← Day 2–3 will add this
    safe_prompt = request.prompt

    # ── (placeholder): Prompt Injection Detection via Rebuff ────────────────
    # check_injection(safe_prompt)                    # ← Week 3 will add this

    import time
    import uuid
    from app.models.audit import AuditLog

    start_time = time.time()
    req_id = str(uuid.uuid4())

    # ── Day 6: Internal LLM (Ollama) ────────────────────────────────────────
    try:
        response_text = await ollama.chat(safe_prompt)
        status = "success"
        status_code = 200
        error_msg = None
    except Exception as e:
        response_text = None
        status = "error"
        status_code = getattr(e, "status_code", 500)
        error_msg = str(e)

    latency_ms = int((time.time() - start_time) * 1000)

    # ── Audit Logging via PostgreSQL ────────────────────────────────────────
    try:
        log_entry = AuditLog(
            request_id=req_id,
            user_id=_token_identifier(user_token),
            provider="ollama",
            model=ollama.model,
            prompt=request.prompt,
            response=response_text,
            status=status,
            status_code=status_code,
            error_message=error_msg,
            latency_ms=latency_ms,
        )
        db.add(log_entry)
        db.commit()
    except Exception as db_err:
        logger.error(f"Failed to write audit log to database: {db_err}")
        db.rollback()

    if status == "error":
        raise HTTPException(status_code=status_code, detail=error_msg)

    # ── (placeholder): Response Content Safety ──────────────────────────────
    # response_text = safety_screen(response_text)   # ← future

    return SimpleChatResponse(
        success=True,
        response=response_text,
        model=ollama.model,
        pii_summary=pii_summary,
    )
