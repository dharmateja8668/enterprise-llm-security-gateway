"""
app/providers/factory.py

Provider factory — maps provider name strings to provider instances.
Supported provider keys:
    "openai"    — OpenAIProvider (cloud, requires OPENAI_API_KEY)
    "anthropic" — AnthropicProvider (cloud, requires ANTHROPIC_API_KEY)
    "ollama"    — OllamaProvider (local, requires a running Ollama server)
"""

import uuid
from fastapi import HTTPException
from app.providers.base import BaseProvider
from app.providers.openai import OpenAIProvider
from app.providers.anthropic import AnthropicProvider
from app.models.schemas import ChatRequest, ChatResponse


# ---------------------------------------------------------------------------
# Thin adapter: wraps OllamaProvider.chat() in the ChatResponse envelope
# that the /v1/chat/completions route expects.
# ---------------------------------------------------------------------------

class _OllamaProviderAdapter(BaseProvider):
    """
    Adapts OllamaProvider.chat() (plain-text in/out) to the ChatRequest /
    ChatResponse contract used by the /v1/chat/completions gateway route.

    This keeps the OllamaProvider itself simple (plain prompt → plain response)
    while letting ProviderFactory return a fully conformant BaseProvider.
    """

    def __init__(self):
        # Import here to avoid a circular import at module load time.
        from app.providers.ollama import OllamaProvider
        self._ollama = OllamaProvider()

    async def chat_completions(self, request: ChatRequest) -> ChatResponse:
        # Concatenate all user messages into a single prompt string.
        prompt = "\n".join(
            msg.content for msg in request.messages if msg.role == "user"
        ) or "\n".join(msg.content for msg in request.messages)

        response_text = await self._ollama.chat(prompt)

        return ChatResponse(
            id=str(uuid.uuid4()),
            provider="ollama",
            model=self._ollama.model,
            choices=[
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": response_text},
                    "finish_reason": "stop",
                }
            ],
            usage=None,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class ProviderFactory:
    @staticmethod
    def get_provider(provider_name: str) -> BaseProvider:
        """
        Return a provider instance for the given provider name.

        Args:
            provider_name: One of "openai", "anthropic", or "ollama"
                           (case-insensitive).

        Raises:
            HTTPException(400): If the provider name is not recognised.
        """
        provider_name = provider_name.lower()
        if provider_name == "openai":
            return OpenAIProvider()
        elif provider_name == "anthropic":
            return AnthropicProvider()
        elif provider_name == "ollama":
            return _OllamaProviderAdapter()
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unsupported provider: '{provider_name}'. "
                    "Valid options are: openai, anthropic, ollama."
                ),
            )
