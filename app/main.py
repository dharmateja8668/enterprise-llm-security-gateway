"""app/main.py
Enterprise LLM Security Gateway — FastAPI application entrypoint.
"""

from dotenv import load_dotenv
load_dotenv()  # must happen before any module that reads os.getenv()

from fastapi import FastAPI
from app.db import engine, Base
from app.routes.chat import router as chat_router
from app.routes.basic_chat import router as basic_chat_router
from app.providers.ollama import OllamaProvider

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description=(
        "Secure proxy gateway for LLM APIs — powered by Ollama (internal LLM).\n\n"
        "**Security flow:** Authentication → Rate Limiting → PII/PHI Redaction → "
        "Prompt Injection Detection → Ollama LLM → Response Safety → Audit Logging.\n\n"
        "**Primary endpoint:** `POST /chat` (authenticated, rate-limited).\n\n"
        "**Quick start:** Send `Authorization: Bearer <GATEWAY_API_KEY>` with every request."
    ),
    version="1.0.0",
)

# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

@app.get("/", tags=["Health"])
async def root():
    return {"message": "Enterprise LLM Security Gateway is running."}

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy"}

@app.get("/health/ollama", tags=["Health"])
async def ollama_health():
    """
    Check whether Ollama is reachable and the configured model is available.

    Returns:
        - ollama_reachable: bool
        - base_url: str
        - model: str
        - model_available: bool
        - available_models: list[str]

    Safe to call without authentication — reveals no secrets.
    """
    provider = OllamaProvider()
    return await provider.health_check()

app.include_router(basic_chat_router)  # POST /chat  (authenticated gateway)
app.include_router(chat_router)        # POST /v1/chat/completions (provider-routed)
