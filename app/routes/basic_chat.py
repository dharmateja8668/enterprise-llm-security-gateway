"""
app/routes/basic_chat.py
POST /chat — The primary gateway chat endpoint.

Security flow (Day 1–6):
  1. Authentication     — verify_api_key()       → 401 if missing/invalid
  2. Rate Limiting      — check_rate_limit()     → 429 if over 10 req/min
  3. PII/PHI Redaction  — (planned: Presidio)    → strips PII before LLM sees it
  4. Injection Detection— (planned: Rebuff)      → rejects malicious prompts
  5. Ollama LLM         — OllamaProvider.chat()  → real model response
  6. Content Safety     — (planned)              → screens response
  7. Audit Logging      — (planned: PostgreSQL)  → records interaction
"""

from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from app.security.auth import verify_api_key
from app.security.rate_limiter import check_rate_limit
from app.providers.ollama import OllamaProvider
from sqlalchemy.orm import Session
from app.models.log import RequestLog
from app.db import get_db
import hashlib

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


class SimpleChatResponse(BaseModel):
    success: bool
    response: str
    model: str


@router.post("/chat", response_model=SimpleChatResponse)
async def chat_endpoint(
    request: SimpleChatRequest,
    user_token: str = Depends(verify_api_key), db: Session = Depends(get_db),
):
    """
    POST /chat — authenticated, rate-limited gateway to the internal Ollama LLM.

    Full request flow:
      User → FastAPI → Auth (Day 4) → Rate Limit (Day 5) → Ollama (Day 6) → User
    """
    ollama = _get_ollama()
    
    # ── Day 4: Authentication (enforced by Depends above) ──────────────────
    # verify_api_key() already ran; user_token holds the validated token.

    # ── Day 5: Rate Limiting ────────────────────────────────────────────────
    check_rate_limit(user_token)

    # ── Day 6a: Input validation ────────────────────────────────────────────
    if not request.prompt or not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    # ── Day 6b (placeholder): PII/PHI Redaction via Microsoft Presidio ──────
    # safe_prompt = presidio_redact(request.prompt)   # <── Day 7 will add this
    safe_prompt = request.prompt

    # ── Day 6c (placeholder): Prompt Injection Detection via Rebuff ─────────
    # check_injection(safe_prompt)                    # <── Day 7 will add this

    # ── Day 6: Internal LLM (Ollama) ────────────────────────────────────────
    try:
        response_text = await ollama.chat(safe_prompt)
    except Exception as e:
        # Log the failure before returning the error to the user
        log_entry = RequestLog(
            user_token=_token_identifier(user_token),
            provider="ollama",
            model=ollama.model,
            prompt=request.prompt,
            status="error",
        )
        db.add(log_entry)
        db.commit()
        raise

    # ── Day 6d (placeholder): Response Content Safety ───────────────────────
    # response_text = safety_screen(response_text)   # <── Day 7 will add this

    # ── Day 6e (placeholder): Audit Logging via PostgreSQL ──────────────────
    # Log request and response to PostgreSQL
    log_entry = RequestLog(
        user_token=_token_identifier(user_token),
        provider="ollama",
        model=ollama.model,
        prompt=request.prompt,
        status="success",
    )
    db.add(log_entry)
    db.commit()

    return SimpleChatResponse(
        success=True,
        response=response_text,
        model=ollama.model,
    )
