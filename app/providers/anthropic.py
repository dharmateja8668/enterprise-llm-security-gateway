import os
import httpx
import uuid
from fastapi import HTTPException
from app.providers.base import BaseProvider
from app.models.schemas import ChatRequest, ChatResponse

class AnthropicProvider(BaseProvider):
    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.base_url = "https://api.anthropic.com/v1"

    async def chat_completions(self, request: ChatRequest) -> ChatResponse:
        if not self.api_key:
            raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY is not configured")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        system_prompt = ""
        anthropic_messages = []
        for msg in request.messages:
            if msg.role == "system":
                system_prompt += msg.content + "\n"
            else:
                anthropic_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })

        payload = {
            "model": request.model,
            "messages": anthropic_messages,
            "max_tokens": request.max_tokens or 1024,
            "temperature": request.temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt.strip()

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/messages",
                    headers=headers,
                    json=payload,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                
                choices = [{
                    "message": {
                        "role": "assistant",
                        "content": data.get("content", [{"text": ""}])[0].get("text", "")
                    },
                    "finish_reason": data.get("stop_reason", "stop")
                }]
                
                return ChatResponse(
                    id=data.get("id", str(uuid.uuid4())),
                    provider="anthropic",
                    model=request.model,
                    choices=choices,
                    usage=data.get("usage", {})
                )
            except httpx.HTTPStatusError as e:
                raise HTTPException(status_code=e.response.status_code, detail=f"Anthropic API Error: {e.response.text}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error communicating with Anthropic: {str(e)}")
