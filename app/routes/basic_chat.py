from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.services.mock_llm import MockLLMService
from app.security.auth import verify_api_key

router = APIRouter(tags=["Day 3 Chat"])
mock_llm_service = MockLLMService()

class SimpleChatRequest(BaseModel):
    prompt: str

class SimpleChatResponse(BaseModel):
    success: bool
    response: str

@router.post("/chat", response_model=SimpleChatResponse, dependencies=[Depends(verify_api_key)])
async def chat_endpoint(request: SimpleChatRequest):
    # Handle empty prompt
    if not request.prompt or not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    # Process through mock LLM
    response_text = await mock_llm_service.generate_response(request.prompt)
    
    return SimpleChatResponse(success=True, response=response_text)
