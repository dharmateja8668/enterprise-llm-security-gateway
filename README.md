# Enterprise LLM & GenAI Security Gateway

## Project Description

The Enterprise LLM Security Gateway is a secure proxy service that sits between internal corporate applications/users and external LLM providers (like OpenAI and Anthropic) or internal LLMs.

## Problem Statement

When corporate users and applications send prompts directly to external LLM APIs, it creates significant risks of data leakage (such as exposing PII or PHI) and malicious prompt injections. A centralized security gateway is needed to enforce compliance, intercept unsafe content, and audit all AI interactions before they leave the corporate network.

## Project Objective

The objective of this project is to provide a robust, secure proxy layer for enterprise LLM usage that seamlessly routes requests while enforcing critical security and auditing policies.

## Architecture

Internal Application
        |
        v
FastAPI Security Gateway
        |
        v
Provider Routing Layer
        |
        +------> OpenAI
        |
        +------> Anthropic
        |
        +------> Internal LLM
        |
        v
Response
        |
        v
FastAPI Security Gateway
        |
        v
Internal Application

## Technology Stack

- Python (Day 1)
- FastAPI (Day 1)
- LangChain (Planned)
- Microsoft Presidio (Planned)
- Rebuff (Planned)
- PostgreSQL (Planned)
- Redis (Planned)
- Docker (Planned)
- Kubernetes (Planned)

## Current Project Status (Day 2 Completed)

Day 1 Completed:
- Initial project structure, FastAPI foundation, architecture design

Day 2 Completed:
- Basic working LLM proxy gateway
- POST `/v1/chat/completions` endpoint implemented
- Pydantic models for structured requests and responses
- Provider abstraction interface (OpenAI & Anthropic)
- Dynamic routing based on the `provider` field in the request
- Basic error handling and validation
- Configuration via environment variables (`.env`)
- Unit tests for validation and routing

### How to Run the Gateway

1. Configure environment variables in a `.env` file (or export them):
   ```env
   OPENAI_API_KEY=your-openai-api-key
   ANTHROPIC_API_KEY=your-anthropic-api-key
   ```
   **Important:** Never hardcode your API keys.

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

4. Verify it's running by checking the interactive docs:
   Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.

### Making a Request

Send a POST request to `/v1/chat/completions`:

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/v1/chat/completions' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "provider": "openai",
  "model": "gpt-4o",
  "messages": [
    {
      "role": "user",
      "content": "Hello! What is your name?"
    }
  ]
}'
```

## Future Development Plan

Later stages will implement:
- LLM provider proxy routing
- Authentication
- Redis rate limiting
- PostgreSQL audit logging
- Microsoft Presidio PII/PHI detection and redaction
- Rebuff prompt injection detection
- Response/content safety
- RBAC
- SOC dashboard
- Docker
- Kubernetes deployment
