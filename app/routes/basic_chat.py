from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.services.mock_llm import MockLLMService
from app.security.auth import verify_api_key
from app.security.rate_limiter import check_rate_limit

router = APIRouter(tags=["Day 3 Chat"])
mock_llm_service = MockLLMService()

class SimpleChatRequest(BaseModel):
    prompt: str

class SimpleChatResponse(BaseModel):
    success: bool
    response: str

@router.post("/chat", response_model=SimpleChatResponse)
async def chat_endpoint(
    request: SimpleChatRequest,
    user_token: str = Depends(verify_api_key),
):
    """
    POST /chat — authenticated and rate-limited chat endpoint.

    Request flow:
      1. Day 4 Authentication  → verify_api_key (401 if missing/invalid)
      2. Day 5 Rate Limiting   → check_rate_limit (429 if over 10 req/min)
      3. Mock LLM              → generate_response
    """
    # Day 5: Enforce per-user rate limit (runs AFTER successful authentication)
    check_rate_limit(user_token)

    # Handle empty prompt
    if not request.prompt or not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    # Process through mock LLM
    response_text = await mock_llm_service.generate_response(request.prompt)

    return SimpleChatResponse(success=True, response=response_text)
