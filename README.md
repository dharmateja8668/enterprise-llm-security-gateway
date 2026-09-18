# Enterprise LLM & GenAI Security Gateway
Enterprise LLM & GenAI Security Gateway — Zaalima Internship Project

## Project Description

The Enterprise LLM Security Gateway is a high-performance, secure proxy service positioned between internal enterprise applications and internal or external LLM providers (such as Ollama, OpenAI, and Anthropic).

## Problem Statement

When enterprise users and automated services send prompts directly to LLM APIs, confidential data (PII, PHI, financial records, internal project identifiers) risks leakage, training exposure, and regulatory violations. Additionally, direct connections expose systems to prompt injection attacks without centralized audit trails. A centralized security gateway intercepts unsafe content, enforces enterprise compliance, anonymizes sensitive data before egress, and logs interactions securely.

## Architecture

```text
User / Internal App
        |
        v
FastAPI Security Gateway
        |
        v
[Day 4] Authentication (Bearer token verification)
        |
        v
[Day 5] Redis Rate Limiter (Token bucket / 10 req/min/user)
        |
        v
[Week 2 Day 1-3] Presidio PII Detection
        |
        v
[Week 2 Day 4-6] PII Anonymization -> <PII_PERSON_1>
        |  (Collision protection & reverse mapping)
        v
Provider Routing Layer (Ollama / OpenAI / Mock)
        |
        v  (Raw PII NEVER reaches LLM)
LLM Response (containing placeholders or text)
        |
        v
[Week 2 Day 6] PII Deanonymization -> restores original values
        |  (Controlled variants: <PII_...>, [PII_...], PII_...)
        v
Audit Logging (PostgreSQL stores only anonymized prompts & metadata)
        |
        v
Client Receives Restored Response
```

---

## PII Anonymization & Deanonymization (Week 2, Day 4–6)

### 1. Standardized Placeholder System
Detected PII entities are replaced with deterministic, collision-resistant placeholders formatted as:
```text
<PII_{ENTITY_TYPE}_{INDEX}>
```
Examples:
- `<PII_PERSON_1>`
- `<PII_EMAIL_ADDRESS_1>`
- `<PII_CREDIT_CARD_1>`
- `<PII_SSN_1>`
- `<PII_INTERNAL_PROJECT_CODE_1>`

**Entity Normalization**:
- `US_SSN` $\rightarrow$ `SSN`
- `US_PASSPORT` $\rightarrow$ `PASSPORT`
- `US_DRIVER_LICENSE` $\rightarrow$ `DRIVER_LICENSE`

### 2. Request-Scoped In-Memory Mapping
- Mappings (`{"<PII_PERSON_1>": "Rahul"}`) exist strictly in-memory during the lifetime of a single request.
- The mapping dictionary is **never logged**, **never stored in the database**, and **never sent to the LLM or client**.
- **Repeated Entities**: If the same entity appears multiple times in a prompt (e.g. `Rahul contacted Rahul`), both instances receive the identical placeholder (`<PII_PERSON_1>`). Different entities receive sequential distinct indices (`<PII_PERSON_1>`, `<PII_PERSON_2>`).

### 3. Placeholder Collision Protection
If a user prompt already contains text that resembles a placeholder (e.g. `My doc mentions <PII_PERSON_1>. My name is Rahul.`):
- The anonymizer pre-scans the input for pre-existing placeholder tokens.
- All pre-existing indices for that entity type are reserved.
- Newly detected PII starts above the reserved indices (assigning `<PII_PERSON_2>` to `Rahul`).
- The user's pre-existing text is not mapped and is **never accidentally overwritten** during deanonymization.

### 4. Controlled LLM Variant Handling
LLMs may modify placeholder syntax in their responses. The gateway supports controlled, unambiguous formats:
- **Standard angle brackets**: `<PII_PERSON_1>`, `< PII_PERSON_1 >`
- **Square brackets**: `[PII_PERSON_1]`, `[ PII_PERSON_1 ]`
- **Standalone bare tokens**: `PII_PERSON_1` (bounded by word/bracket boundaries `(?<![<\[\w])CORE(?![>\]\w])`)
- **Case-insensitivity**: `<pii_person_1>`, `[Pii_Person_1]`
- **Legacy placeholders**: `<PERSON_1>`, `[PERSON_1]` (backward-compatible with existing test suites)

### 5. Fail-Closed Security Guarantees
- **No Hallucinations / No Guesses**: If the LLM omits a placeholder entirely, the gateway does not attempt to guess where the original PII belongs. The response is returned as-is.
- **Malformed / Partial Placeholders**: Unbalanced or partial tokens (e.g., `<PII_PERSON_1`, `PII_PERSON_1>`, or `<PII_PERSON_`) are **left strictly unchanged** to prevent incorrect restoration.
- **Unknown Placeholders**: Any placeholder not generated in the current request's mapping is ignored.
- **No Broad Replacements**: The gateway never performs unchecked string replacements (such as `text.replace("Rahul", ...)`), preventing accidental replacement of legitimate text.
- **Fail-Closed on Scanner Failure**: If Presidio or the anonymizer throws an exception, the request fails closed with HTTP 500 (`"Security scanning failed; request rejected for safety"`). Raw prompts are never forwarded to the LLM upon scanner failure.

### 6. Logging & Audit Security
- **PostgreSQL Audit Logs**: The `RequestLog.prompt` field stores exclusively `safe_prompt` (anonymized), never raw PII.
- **Application & Debug Logs**: Only high-level entity counts and types are logged (e.g. `PII detected: 2 entit(ies), types=['EMAIL_ADDRESS', 'PERSON']`).
- **No Token Leaks**: User tokens are hashed with SHA-256 before logging (`_token_identifier`).

---

## Running Tests

Run the complete test suite:
```powershell
.\venv\Scripts\pytest -v
```

Run only PII anonymization tests:
```powershell
.\venv\Scripts\pytest tests/test_anonymization.py -v
```

Run manual synthetic verification across `/chat`:
```powershell
.\venv\Scripts\python verify_manual_chat.py
```

---

## Known Limitations

1. **LLM Context Awareness**: Highly degraded or summarized LLM responses that omit placeholders will not have PII restored. This is by design to prioritize data privacy over speculative text reconstruction.
2. **Unsupported Bracket Formats**: Unusual bracket variations such as `{{PII_PERSON_1}}` or `(PII_PERSON_1)` with internal punctuation are left un-restored to avoid collision with programming syntax.
3. **Presidio Statistical Sensitivity**: Detection accuracy relies on Presidio recognizers and spaCy language models. Rare name structures without sentence context may require custom pattern recognizers.

---

## Technology Stack

- **Python 3.13 / FastAPI**: High-performance asynchronous API framework.
- **Microsoft Presidio**: Enterprise PII detection engine (`presidio-analyzer`).
- **Ollama**: Local LLM engine (`tinyllama`, `llama3.2:3b`).
- **PostgreSQL / SQLAlchemy**: Secure audit logging.
- **Redis / FakeRedis**: Sliding-window rate limiting (10 req/min/user).
- **pytest / respx / fakeredis**: Automated test framework with complete provider isolation.
