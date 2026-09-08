from fastapi import FastAPI

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for LLM APIs"
)

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Enterprise LLM Security Gateway is running."}

@app.get("/")
async def root():
    return {"message": "Welcome to the Enterprise LLM Security Gateway"}
