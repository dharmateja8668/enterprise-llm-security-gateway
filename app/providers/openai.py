import os
import httpx
import uuid
from fastapi import HTTPException
from app.providers.base import BaseProvider
from app.models.schemas import ChatRequest, ChatResponse

class OpenAIProvider(BaseProvider):
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = "https://api.openai.com/v1"

    async def chat_completions(self, request: ChatRequest) -> ChatResponse:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": request.model,
            "messages": [msg.model_dump() for msg in request.messages],
            "temperature": request.temperature,
        }
        if request.max_tokens:
            payload["max_tokens"] = request.max_tokens

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                
                return ChatResponse(
                    id=data.get("id", str(uuid.uuid4())),
                    provider="openai",
                    model=request.model,
                    choices=data.get("choices", []),
                    usage=data.get("usage", {})
                )
            except httpx.HTTPStatusError as e:
                raise HTTPException(status_code=e.response.status_code, detail=f"OpenAI API Error: {e.response.text}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error communicating with OpenAI: {str(e)}")
