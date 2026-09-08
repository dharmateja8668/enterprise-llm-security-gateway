# Enterprise LLM & GenAI Security Gateway

## What is the Enterprise LLM Security Gateway?
The Enterprise LLM Security Gateway is a secure proxy service that sits between internal corporate users or applications and external Large Language Model (LLM) APIs, such as OpenAI or Anthropic, as well as internal LLMs. 

## Why is the gateway placed between the internal application and LLM provider?
By positioning the gateway in the middle, the organization can enforce centralized security, compliance, and auditing policies. It prevents direct access to LLM APIs, ensuring that all interactions are monitored and scrubbed for sensitive data before leaving the corporate network.

## What a proxy means in this project
In this project, a proxy acts as an intermediary. When an internal application wants to send a prompt to an LLM, it sends the prompt to our FastAPI gateway instead. The gateway processes the request, optionally modifies it (like removing PII), forwards it to the actual LLM provider, receives the response, and then sends the final response back to the internal application.

## How requests will flow through the gateway
1. The internal application sends a prompt to the gateway.
2. The gateway routes the request to the appropriate LLM provider.
3. The response from the LLM provider is received by the gateway.
4. The gateway sends the response back to the internal application.

## Architecture Diagram
`mermaid
flowchart TD
    A[Internal User / Application] --> B[FastAPI Security Gateway]
    B --> C[Provider Routing Layer]
    C --> D[OpenAI]
    C --> E[Anthropic]
    C --> F[Internal LLM]
    D --> B
    E --> B
    F --> B
    B --> A
`

## How the architecture will support multiple LLM providers
The Gateway includes a Provider Routing Layer that abstracts the underlying LLM APIs. This allows the internal application to use a unified interface, while the gateway handles the specific API formats and credentials for OpenAI, Anthropic, or internal models.

## Future Components
The following security layers will be placed inside the gateway in later weeks. **Note: These are FUTURE components and are not implemented today.**
- Authentication
- Redis rate limiting
- PII/PHI detection and redaction using Microsoft Presidio
- Prompt injection detection using Rebuff
- Response/content safety checks
- PostgreSQL audit logging
- RBAC
