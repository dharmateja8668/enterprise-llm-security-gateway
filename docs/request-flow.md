# Request Flow Lifecycle

This document outlines the planned lifecycle of a request as it travels through the Enterprise LLM Security Gateway.

**Step 1:**
Internal application sends a prompt to the Security Gateway.

**Step 2:**
FastAPI receives the request.

**Step 3:**
Gateway identifies the requested LLM provider.

**Step 4:**
Gateway performs security checks.
*(These checks are planned for later implementation.)*

**Step 5:**
Gateway forwards the safe request to the selected LLM provider.

**Step 6:**
LLM provider returns the response.

**Step 7:**
Gateway performs response checks.
*(These checks are planned for later implementation.)*

**Step 8:**
Gateway returns the response to the internal application.
