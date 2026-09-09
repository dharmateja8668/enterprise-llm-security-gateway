from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    provider: str = Field(..., description="The LLM provider to route to (e.g., 'openai', 'anthropic')")
    model: str = Field(..., description="The specific model to use (e.g., 'gpt-4o', 'claude-3-sonnet')")
    messages: List[Message]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None

class ChatResponse(BaseModel):
    id: str
    provider: str
    model: str
    choices: List[Dict[str, Any]]
    usage: Optional[Dict[str, Any]] = None
