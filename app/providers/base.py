from abc import ABC, abstractmethod
from app.models.schemas import ChatRequest, ChatResponse

class BaseProvider(ABC):
    """Abstract base class for all LLM providers."""
    
    @abstractmethod
    async def chat_completions(self, request: ChatRequest) -> ChatResponse:
        """Process a chat completion request."""
        pass
