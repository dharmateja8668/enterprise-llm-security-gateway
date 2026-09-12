# Enterprise LLM & GenAI Security Gateway

## Project Description

The Enterprise LLM Security Gateway is a secure proxy service that sits between internal corporate applications/users and external LLM providers (like OpenAI and Anthropic) or internal LLMs.

## Problem Statement

When corporate users and applications send prompts directly to external LLM APIs, it creates significant risks of data leakage (such as exposing PII or PHI) and malicious prompt injections. A centralized security gateway is needed to enforce compliance, intercept unsafe content, and audit all AI interactions before they leave the corporate network.

## Project Objective

The objective of this project is to provide a robust, secure proxy layer for enterprise LLM usage that seamlessly routes requests while enforcing critical security and auditing policies.

## Architecture

```
Internal Application
        |
        v
FastAPI Security Gateway
        |
        v
Day 4 Authentication (Bearer token)
        |
        v
Day 5 Redis Rate Limiter (10 req/min/user)
        |
        v
Provider Routing Layer
        |
        +------> OpenAI
        |
        +------> Anthropic
        |
        +------> Internal LLM (Mock)
        |
        v
Response
        |
        v
Internal Application
```

## Technology Stack

- Python (Day 1)
- FastAPI (Day 1)
- LangChain (Planned)
- Microsoft Presidio (Planned)
- Rebuff (Planned)
- PostgreSQL (Planned)
- **Redis — Day 5 Rate Limiting (Active)**
- Docker (Planned)
- Kubernetes (Planned)

## Current Project Status (Day 5 Completed)

Day 1 Completed:
- Initial project structure, FastAPI foundation, architecture design

Day 2 Completed:
- Basic working LLM proxy gateway routing structure

Day 3 Completed:
- Mock LLM Core Routing implemented
- GET `/health` endpoint returning `{"status": "healthy"}`
- POST `/chat` endpoint with basic Pydantic validation
- Modular mock LLM service

Day 4 Completed:
- API key authentication via `Authorization: Bearer <token>` header
- `GATEWAY_API_KEY` environment variable for secure token configuration
- `/chat` requires authentication; `/health` remains public
- 401 Unauthorized for missing or invalid tokens

Day 5 Completed:
- **Redis-based rate limiting** — 10 requests per minute per authenticated user
- Per-user counters stored in Redis (keyed by user token)
- `429 Too Many Requests` with `Retry-After` header when limit exceeded
- `REDIS_URL` environment variable for Redis configuration
- Rate limiting applies **only after** successful authentication
- `/health` is **not** rate limited

---

## Rate Limiting (Day 5)

### What it does

Every authenticated user is allowed **10 requests per 60-second window** to the `/chat` endpoint.
Each user's counter is tracked independently in Redis, so one user being rate-limited does not affect other users.

The 60-second window starts on the **first request** made by that user and resets automatically when the window expires.

### Current limit

| Limit | Value |
|-------|-------|
| Requests per window | **10** |
| Window duration | **60 seconds** |
| Scope | Per authenticated user token |

### How it works (technical)

```
POST /chat
  │
  ├─► verify_api_key()          ← Day 4 auth (401 if invalid)
  │
  └─► check_rate_limit(token)   ← Day 5 Redis INCR
        │
        ├─ counter ≤ 10  →  proceed to mock LLM  →  200 OK
        │
        └─ counter > 10  →  429 Too Many Requests
                              Retry-After: <seconds until window resets>
```

The rate limiter uses Redis `INCR` + `EXPIRE`:
1. `INCR rate_limit:<token>` — atomically increment the counter
2. On first request (`count == 1`) — `EXPIRE` is set to 60 seconds
3. If `count > 10` — return `429` with `Retry-After` header

### Redis configuration

Set the `REDIS_URL` environment variable (in `.env` or shell):

```env
REDIS_URL=redis://localhost:6379
```

**Default:** `redis://localhost:6379` (used when `REDIS_URL` is not set).

Never hard-code Redis passwords or credentials. Use environment variables.

#### With Redis authentication (ACL / password):
```env
REDIS_URL=redis://:yourpassword@localhost:6379
```

#### With Redis on a remote host:
```env
REDIS_URL=redis://redis-host:6379
```

### Running Redis locally

**Option 1 — Docker (recommended):**
```bash
docker run -d --name redis-gateway -p 6379:6379 redis:7-alpine
```

**Option 2 — WSL (Windows Subsystem for Linux):**
```bash
sudo apt-get install redis-server
redis-server
```

**Option 3 — Windows native (via Memurai or Redis for Windows):**
Download from https://github.com/microsoftarchive/redis/releases or use Memurai.

**Verify Redis is running:**
```bash
redis-cli ping
# Expected output: PONG
```

### Example 429 response

When the rate limit is exceeded:

**HTTP Status:** `429 Too Many Requests`

**Response Headers:**
```
Retry-After: 42
```

**Response Body:**
```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

---

## How to Run the Gateway

1. Configure environment variables in a `.env` file (or export them):
   ```env
   OPENAI_API_KEY=your-openai-api-key
   ANTHROPIC_API_KEY=your-anthropic-api-key
   GATEWAY_API_KEY=your-secret-gateway-token
   REDIS_URL=redis://localhost:6379
   ```
   **Important:** Never hardcode API keys, tokens, or passwords.

2. Start Redis (see "Running Redis locally" above).

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

5. Verify it's running by checking the interactive docs:
   Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.

---

## Available Endpoints & Examples

### 1. Health Endpoint (`GET /health`)
Used to verify the gateway is up and running.
**No authentication required. Not rate limited.**

**Example Request:**
```bash
curl -X 'GET' 'http://127.0.0.1:8000/health'
```

**Example Response:**
```json
{
  "status": "healthy"
}
```

---

### 2. Chat Endpoint (`POST /chat`)
Sends a prompt to the Mock LLM.
**Requires Bearer token authentication. Rate limited to 10 req/min/user.**

**Example Request:**
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/chat' \
  -H 'Authorization: Bearer your-secret-gateway-token' \
  -H 'Content-Type: application/json' \
  -d '{"prompt": "Explain cybersecurity"}'
```

**Example Response (200 OK):**
```json
{
  "success": true,
  "response": "This is a mock LLM response."
}
```

**Example Response (401 Unauthorized):**
```json
{
  "detail": "Authentication required"
}
```

**Example Response (429 Too Many Requests):**
```
HTTP/1.1 429 Too Many Requests
Retry-After: 42
```
```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

---

### 3. Advanced Chat Completions (`POST /v1/chat/completions`)
Provider-routing endpoint for OpenAI/Anthropic.

**Example Request:**
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -d '{
  "provider": "openai",
  "model": "gpt-4o",
  "messages": [{"role": "user", "content": "Hello!"}]
}'
```

---

## Running Tests

```bash
pytest -q
```

Tests use `fakeredis` — **no real Redis server is needed to run tests.**

---

## Future Development Plan

Later stages will implement:
- LLM provider proxy routing
- PostgreSQL audit logging
- Microsoft Presidio PII/PHI detection and redaction
- Rebuff prompt injection detection
- Response/content safety
- RBAC
- SOC dashboard
- Docker
- Kubernetes deployment
