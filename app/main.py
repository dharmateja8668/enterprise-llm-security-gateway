"""app/main.py
Enterprise LLM Security Gateway — FastAPI application entrypoint.
"""

from dotenv import load_dotenv
load_dotenv()  # must happen before any module that reads os.getenv()

from fastapi import FastAPI
from app.db import engine, Base, SessionLocal
from app.models import audit
from app.routes.chat import router as chat_router
from app.routes.basic_chat import router as basic_chat_router
from app.routes.pii import router as pii_router
from app.routes.rbac import router as rbac_router
from app.routes.dashboard import router as dashboard_router
from app.providers.ollama import OllamaProvider
from app.security.rbac import init_default_rbac_policies

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

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        init_default_rbac_policies(db)
    finally:
        db.close()

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

from app.routes.auth import router as auth_router
from app.routes.chat_sessions import router as chat_sessions_router

app.include_router(auth_router)          # POST /auth/login, POST /auth/logout, GET /auth/me
app.include_router(chat_sessions_router) # GET /chats, GET /chats/{id}, POST /chats, DELETE /chats/{id}
app.include_router(basic_chat_router)     # POST /chat  (authenticated gateway)
app.include_router(chat_router)           # POST /v1/chat/completions (provider-routed)
app.include_router(pii_router)            # POST /pii/scan (PII detection — Week 2)
app.include_router(rbac_router)           # RBAC policy management
app.include_router(dashboard_router)      # GET /dashboard (SOC Compliance Dashboard)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8081, reload=True)
