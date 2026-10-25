from fastapi import APIRouter
from app.models.schemas import ChatRequest, ChatResponse
from app.providers.factory import ProviderFactory

router = APIRouter(prefix="/v1", tags=["Chat"])

from fastapi import Depends
from sqlalchemy.orm import Session
import time
from app.db import get_db
from app.models.audit import AuditLog

@router.post("/chat/completions", response_model=ChatResponse)
async def create_chat_completion(request: ChatRequest, db: Session = Depends(get_db)):
    start_time = time.monotonic()
    request_id = getattr(request, "request_id", None)
    # Ensure request_id exists; fallback to generated uuid if needed
    if not request_id:
        import uuid
        request_id = str(uuid.uuid4())
    
    user_id = getattr(request, "user_id", None)
    if user_id:
        from app.security.rbac import check_rbac_access
        from fastapi import HTTPException
        if not check_rbac_access(db, user_id, request.model):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "AI model access denied",
                    "blocked": True,
                    "reason": "rbac_model_access_denied",
                },
            )

    provider = ProviderFactory.get_provider(request.provider)
    try:
        response = await provider.chat_completions(request)
        latency_ms = int((time.monotonic() - start_time) * 1000)

        audit_record = AuditLog(
            request_id=request_id,
            user_id=getattr(request, "user_id", None),
            provider=request.provider,
            model=request.model,
            prompt=str(request.messages),
            response=str(response),
            status="success",
            latency_ms=latency_ms,
        )
        db.add(audit_record)
        db.commit()
        return response
    except Exception as exc:
        latency_ms = int((time.monotonic() - start_time) * 1000)
        audit_record = AuditLog(
            request_id=request_id,
            user_id=getattr(request, "user_id", None),
            provider=request.provider,
            model=request.model,
            prompt=str(request.messages),
            response=None,
            status="error",
            error_message=str(exc),
            latency_ms=latency_ms,
        )
        db.add(audit_record)
        db.commit()
        raise
