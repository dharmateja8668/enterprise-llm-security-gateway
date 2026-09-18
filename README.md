# Enterprise LLM & GenAI Security Gateway
Enterprise LLM & GenAI Security Gateway - Zaalima Internship Project


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
Week 2 Day 4-6: PII Anonymization (Presidio) -> <PERSON_1>
        |
        v
Provider Routing Layer
        |
        +------> Ollama / OpenAI / Mock
        |
        v
Response (with placeholders)
        |
        v
Week 2 Day 6: PII Deanonymization -> restores Rahul
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
- PostgreSQL (Day 6 Logging — Active)
- **Redis — Day 5 Rate Limiting (Active)**
- Microsoft Presidio (Planned)
- Rebuff (Planned)
- Docker (Planned)
- Kubernetes (Planned)

## Current Status (Week 2, Day 4-6)

Completed:
- PII Detection using Microsoft Presidio (Week 2, Day 1-3).
- **PII Anonymization (Week 2, Day 4):** Replaces sensitive information with deterministic placeholders (e.g., `<PERSON_1>`).
- **Secure LLM Integration (Week 2, Day 5):** Anonymized prompt is sent to the LLM (Ollama). The raw PII is never exposed to the external LLM. Audit logs only save the anonymized prompts.
- **Deanonymization (Week 2, Day 6):** The response from the LLM containing placeholders is restored to the original values using a request-scoped mapping.
- All mapping is correctly handled in-memory within the scope of a single request.

## Future Development Plan

Later stages will implement:
- Prompt injection detection (Rebuff)
- Response/content safety
- RBAC
- SOC dashboard
- Docker
- Kubernetes deployment
