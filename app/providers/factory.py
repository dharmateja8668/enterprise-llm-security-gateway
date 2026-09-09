from fastapi import HTTPException
from app.providers.base import BaseProvider
from app.providers.openai import OpenAIProvider
from app.providers.anthropic import AnthropicProvider

class ProviderFactory:
    @staticmethod
    def get_provider(provider_name: str) -> BaseProvider:
        provider_name = provider_name.lower()
        if provider_name == "openai":
            return OpenAIProvider()
        elif provider_name == "anthropic":
            return AnthropicProvider()
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider_name}")
