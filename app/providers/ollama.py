"""
app/providers/ollama.py
Day 6: Ollama Internal LLM Provider

Connects the Enterprise LLM Security Gateway to a locally running Ollama server.
Ollama exposes an OpenAI-compatible /v1/chat/completions endpoint and its own
native /api/chat endpoint. We use the native endpoint for maximum compatibility
across Ollama versions.

Environment variables (configure in .env or shell):
    OLLAMA_BASE_URL  — Ollama server URL  (default: http://localhost:11434)
    OLLAMA_MODEL     — Model to use       (default: llama3.2:3b)

Do NOT hard-code credentials or model names here.
"""

import os
import httpx
import uuid
from fastapi import HTTPException, status

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _get_base_url() -> str:
    """Return the Ollama base URL from environment, stripping trailing slashes."""
    return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")


def _get_model() -> str:
    """Return the configured Ollama model name."""
    return os.getenv("OLLAMA_MODEL", "llama3.2:3b")


# ---------------------------------------------------------------------------
# OllamaProvider — follows the same interface as the /chat route
# ---------------------------------------------------------------------------

class OllamaProvider:
    """
    Sends requests to a locally running Ollama server using the native
    /api/chat endpoint (streaming disabled — returns a single JSON response).

    API reference: https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    def __init__(self):
        self.base_url: str = _get_base_url()
        self.model: str = _get_model()
        # Total timeout in seconds: 5s connect, 120s read (local models can be slow
        # on first token, especially on CPU-only machines).
        self.timeout = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=5.0)

    async def chat(self, prompt: str) -> str:
        """
        Send a plain-text prompt to Ollama and return the model's response text.

        Uses POST /api/chat with stream=False so the entire response arrives in
        one JSON object — no streaming complexity needed for the gateway.

        Args:
            prompt: The user's input text after PII redaction.

        Returns:
            The model's response as a plain string.

        Raises:
            HTTPException(503): Ollama is not running or unreachable.
            HTTPException(504): Ollama took too long to respond.
            HTTPException(500): Ollama returned an unexpected error.
        """
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,        # single JSON response, not a stream
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                # Ollama /api/chat response shape:
                # { "message": { "role": "assistant", "content": "..." }, ... }
                content = data.get("message", {}).get("content", "")
                if not content:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Ollama returned an empty response.",
                    )
                return content.strip()

            except httpx.ConnectError:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        f"Cannot connect to Ollama at {self.base_url}. "
                        "Make sure Ollama is running: run 'ollama serve' in a terminal."
                    ),
                )
            except httpx.TimeoutException:
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail=(
                        f"Ollama timed out after {self.timeout.read}s. "
                        "The model may be loading for the first time — try again in a moment."
                    ),
                )
            except httpx.HTTPStatusError as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Ollama API error {e.response.status_code}: {e.response.text[:300]}",
                )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Unexpected error communicating with Ollama: {str(e)}",
                )

    async def health_check(self) -> dict:
        """
        Check that Ollama is reachable and the configured model is available.
        Returns a dict with status, base_url, and model (no secrets).
        """
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                r.raise_for_status()
                tags = r.json()
                model_names = [m.get("name", "") for m in tags.get("models", [])]
                model_available = any(
                    self.model in name for name in model_names
                )
                return {
                    "ollama_reachable": True,
                    "base_url": self.base_url,
                    "model": self.model,
                    "model_available": model_available,
                    "available_models": model_names,
                }
        except Exception as e:
            return {
                "ollama_reachable": False,
                "base_url": self.base_url,
                "model": self.model,
                "error": str(e),
            }
