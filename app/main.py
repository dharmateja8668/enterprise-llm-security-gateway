from fastapi import FastAPI
from app.routes.chat import router as chat_router
from app.routes.basic_chat import router as basic_chat_router

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for LLM APIs"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
async def root():
    return {"message": "Welcome to the Enterprise LLM Security Gateway"}

app.include_router(chat_router)
app.include_router(basic_chat_router)
