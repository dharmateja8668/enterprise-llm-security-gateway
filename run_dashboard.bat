@echo off
echo Starting Enterprise LLM Security Gateway on port 8081...
python -m uvicorn app.main:app --port 8081 --reload
pause
