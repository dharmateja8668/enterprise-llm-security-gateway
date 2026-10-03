"""
app/routes/basic_chat.py
POST /chat — The primary gateway chat endpoint.

Security flow (Day 1–6 + Week 2 + Week 3 Day 1):
  1. Authentication      — verify_api_key()           → 401 if missing/invalid
  2. Rate Limiting       — check_rate_limit()         → 429 if over 10 req/min
  3. PII Detection       — analyze_pii()              → detects PII
  4. PII/PHI Anonymization — anonymize()              → strips PII before LLM sees it
  5. Prompt Injection    — check_prompt_injection()   → 403 if injection detected
  6. Ollama LLM          — OllamaProvider.chat()      → real model response
  7. Content Safety      — (planned)                  → screens response
  8. Deanonymization     — deanonymize()              → restores PII placeholders
  9. Audit Logging       — PostgreSQL                 → records interaction
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from app.security.auth import verify_api_key
from app.security.rate_limiter import check_rate_limit
from app.security.prompt_injection import check_prompt_injection
from app.providers.ollama import OllamaProvider
from app.services.pii_analyzer import analyze_pii, summarize_pii
from app.services.pii_anonymizer import anonymize, deanonymize
from sqlalchemy.orm import Session
from app.models.log import RequestLog
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
    user_id: Optional[str] = None


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
    
    # Extract the user from the request or fallback to hashed token
    actual_user = request.user_id if request.user_id else _token_identifier(user_token)
    
    # ── Day 4: Authentication (enforced by Depends above) ──────────────────
    # verify_api_key() already ran; user_token holds the validated token.

    # ── Day 5: Rate Limiting ────────────────────────────────────────────────
    check_rate_limit(user_token)

    # ── Day 6a: Input validation ────────────────────────────────────────────
    if not request.prompt or not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    # ── Week 4: RBAC Policy Verification ─────────────────────────────────────
    from app.security.rbac import check_rbac_access
    target_model = ollama.model
    if not check_rbac_access(db, actual_user, target_model):
        logger.warning(
            "RBAC access denied for user=%s model=%s prompt=%s",
            actual_user,
            target_model,
            request.prompt[:30],
        )
        try:
            import uuid as _uuid
            _blocked_log = RequestLog(
                request_id=str(_uuid.uuid4()),
                user_token=actual_user,
                provider="ollama",
                model=target_model,
                prompt="[REDACTED — RBAC blocked]",
                status="rbac_blocked",
            )
            db.add(_blocked_log)
            db.commit()
        except Exception as _db_err:
            logger.error("Failed to write RBAC audit log: %s", _db_err)
            db.rollback()

        raise HTTPException(
            status_code=403,
            detail={
                "error": "AI model access denied",
                "blocked": True,
                "reason": "rbac_model_access_denied",
            },
        )

    # ── Week 2 Day 1: PII Detection (detection & summary) ─────────────────
    try:
        import asyncio
        pii_entities = await asyncio.to_thread(analyze_pii, request.prompt, score_threshold=0.0)
        pii_summary_data = await asyncio.to_thread(summarize_pii, pii_entities)
        pii_summary = PIISummary(**pii_summary_data)

        if pii_summary.pii_detected:
            logger.warning(
                "PII detected in prompt: %d entit(ies), types=%s",
                pii_summary.count,
                pii_summary.entity_types,
            )

        # ── Week 2 Day 4–6: PII/PHI Anonymization via Presidio ──────────────
        safe_prompt, pii_mapping = await asyncio.to_thread(anonymize, request.prompt)
    except HTTPException:
        raise
    except Exception as scan_err:
        logger.error("Security scanning failed; rejecting request for safety: %s", scan_err)
        raise HTTPException(
            status_code=500,
            detail="Security scanning failed; request rejected for safety",
        )

    # ── Week 3 Day 1: Prompt Injection Detection ─────────────────────────────
    # Run injection detection on the RAW prompt to avoid false positives caused by PII redaction tags (like <PHONE_NUMBER>)
    injection_result = await asyncio.to_thread(check_prompt_injection, request.prompt)
    if injection_result.is_injection:
        logger.warning(
            "Prompt injection blocked: method=%s risk_score=%.3f reason=%s "
            "user_token_hash=%s",
            injection_result.detection_method,
            injection_result.risk_score,
            injection_result.reason,
            _token_identifier(user_token),
        )
        # Log blocked attempt to audit DB before raising.
        try:
            import uuid as _uuid, time as _time
            import asyncio
            _blocked_id = str(_uuid.uuid4())
            _blocked_log = RequestLog(
                request_id=_blocked_id,
                user_token=actual_user,
                provider="ollama",
                model=_get_ollama().model,
                prompt="[REDACTED — injection blocked]",
                status="injection_blocked",
            )
            db.add(_blocked_log)
            db.commit()
        except Exception as _db_err:
            logger.error("Failed to write injection-blocked audit log: %s", _db_err)
            db.rollback()
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Prompt injection detected",
                "blocked": True,
                "reason": injection_result.reason,
                "detection_method": injection_result.detection_method,
            },
        )

    import time
    import uuid

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
        log_entry = RequestLog(
            request_id=req_id,
            user_token=actual_user,
            provider="ollama",
            model=ollama.model,
            prompt=safe_prompt,
            status=status,
        )
        db.add(log_entry)
        db.commit()
    except Exception as db_err:
        logger.error(f"Failed to write audit log to database: {db_err}")
        db.rollback()

    if status == "error":
        raise HTTPException(status_code=status_code, detail=error_msg)

    # ── Week 3 Day 3: Response Content Safety ──────────────────────────────
    if response_text is not None:
        from app.security.content_safety import check_content_safety
        import asyncio
        safety_result = await asyncio.to_thread(check_content_safety, response_text)
        if not safety_result.safe:
            logger.warning(f"Content safety blocked response: {safety_result.category}")
            # Log blocked attempt to audit DB
            try:
                import uuid as _uuid, time as _time
                _blocked_log = RequestLog(
                    request_id=str(_uuid.uuid4()),
                    user_token=actual_user,
                    provider="ollama",
                    model=_get_ollama().model,
                    prompt="[REDACTED — request prompted unsafe response]",
                    status="content_safety_blocked",
                )
                db.add(_blocked_log)
                db.commit()
            except Exception as _db_err:
                logger.error("Failed to write content safety audit log: %s", _db_err)
                db.rollback()
            
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Response blocked by content safety policy",
                    "category": safety_result.category
                }
            )

    # ── Week 2 Day 6: Deanonymization ───────────────────────────────────────
    if response_text is not None:
        final_response = deanonymize(response_text, pii_mapping)
    else:
        final_response = None

    return SimpleChatResponse(
        success=True,
        response=final_response,
        model=ollama.model,
        pii_summary=pii_summary,
    )
