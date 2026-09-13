from fastapi import APIRouter
from app.models.schemas import ChatRequest, ChatResponse
from app.providers.factory import ProviderFactory

router = APIRouter(prefix="/v1", tags=["Chat"])

@router.post("/chat/completions", response_model=ChatResponse)
async def create_chat_completion(request: ChatRequest):
    provider = ProviderFactory.get_provider(request.provider)
    response = await provider.chat_completions(request)
    return response
