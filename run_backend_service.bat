@echo off
REM Production launcher for Zaalima Enterprise LLM Security Gateway
REM Runs using project virtual environment without --reload

cd /d "%~dp0"
set PYTHON_EXE=venv\Scripts\python.exe
set LOG_DIR=logs

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Starting Zaalima Security Gateway on http://127.0.0.1:8081 ...
"%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8081 >> "%LOG_DIR%\backend_stdout.log" 2>> "%LOG_DIR%\backend_stderr.log"
