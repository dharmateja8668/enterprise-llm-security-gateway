# Content Safety Filters (Week 3 Day 3)

## Overview
The Content Safety module (`app/security/content_safety.py`) provides an outbound filtering layer for the Enterprise LLM Security Gateway. It inspects the LLM-generated response *before* returning it to the user and blocks responses that violate the configured corporate safety policy.

## Why Response Filtering is Required
While prompt injection detection protects the LLM from malicious inputs, there is still a risk that the LLM may generate unsafe content. This could happen due to a successful bypass, an accidental unsafe prompt, or model hallucinations. Outbound filtering acts as a defense-in-depth measure to prevent harmful payloads from reaching the user's environment.

## Detection Categories
Currently, the detector focuses on high-risk deterministic categories:
- **destructive_commands**: Commands that attempt to delete or damage systems (e.g., `rm -rf /`, `mkfs`).
- **reverse_shell**: Commands that attempt to establish unauthorized outbound connections (e.g., `nc -e /bin/sh`).
- **credential_stealing**: Specific tools or commands used to steal credentials (e.g., `sekurlsa::logonpasswords`).

## Configuration
The feature is controlled via environment variables in `.env`:
- `CONTENT_SAFETY_ENABLED` (true/false): Enables or disables the filter.
- `CONTENT_SAFETY_THRESHOLD` (float): Configurable threshold for blocking (default 0.7).

## Request/Response Flow
1. User Prompt
2. Prompt Injection Detection
3. PII/DLP Checks
4. LLM Generation
5. **Content Safety Filter**
6. ALLOW / BLOCK
7. User

## Blocked Response Behavior
When a response is blocked:
1. The unsafe response is **discarded** and never sent to the user.
2. A generic safe error message is returned (HTTP 403) with the category.
3. The event is logged in the PostgreSQL audit database as `content_safety_blocked`.

## False-Positive Considerations
The detector uses highly specific regular expressions rather than simple keyword matching. Words like "attack", "malware", or "exploit" will not trigger a block. Educational discussions about cybersecurity are generally permitted unless they contain specific, recognizable payloads.

## Testing Instructions
Run unit tests with:
```bash
pytest tests/test_content_safety.py -v
```
Run the full suite to verify regressions:
```bash
pytest -v
```

## Current Limitations
- **Not foolproof**: The heuristic pattern matching only catches known, explicitly defined payloads. Obfuscated or slightly modified payloads may bypass the filter.
- **Context-blind**: It does not understand the semantic context. An educational prompt asking for a literal string example of a destructive command will still be blocked.
