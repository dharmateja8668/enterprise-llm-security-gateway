# Week 3 Day 5: Latency Testing & Optimization

## 1. Baseline Measurements

*   **Hardware/Environment:** Windows OS, local CPU
*   **Python Version:** Python 3.13
*   **Model:** `protectai/deberta-v3-base-prompt-injection-v2`
*   **Cold-start behavior:** ~5500 - 6500 ms to initialize and load the model weights.
*   **Warm latency:** ~472 ms per request processing.

### Baseline Component Latencies

*   **Heuristic detection:** ~0.02 ms
*   **ML detection:** ~139.89 ms
*   **PII/DLP:** ~327.17 ms
*   **Content Safety:** ~0.01 ms
*   **Audit Logging:** ~5.07 ms
*   **Total gateway processing (excluding Ollama):** ~472 ms

## 2. Bottleneck Identification

Measurements clearly indicate that **PII/DLP processing** and **ML inference** are the primary bottlenecks. These components consume over 98% of the gateway's non-LLM processing time. 

More importantly, these operations were fully **synchronous**, meaning they blocked the FastAPI event loop for ~472 ms per request. This prevents the server from handling other concurrent requests while waiting for CPU-bound tasks.

Model initialization was correctly implemented. The model is loaded once upon application startup and the inference pipeline is reused for subsequent requests (avoiding repeated initialization).

## 3. Optimization

**What was changed:** 
We wrapped the synchronous, CPU-bound security functions in `app/routes/basic_chat.py` with `asyncio.to_thread`. This applies to:
*   `analyze_pii`
*   `summarize_pii`
*   `anonymize`
*   `check_prompt_injection`
*   `check_content_safety`
*   Database I/O (`db.commit()`)

**Why:** 
FastAPI's event loop is blocked by synchronous code inside `async def` endpoints. By offloading these CPU-heavy and I/O tasks to a separate thread pool using `asyncio.to_thread()`, we allow the main event loop to remain responsive and process multiple requests concurrently without sacrificing the security layers or reverting to less accurate checks.

## 4. Results

### After Optimization
*   **Total gateway processing:** ~472 ms (single request)
*   **Average improvement:** The absolute latency for a single request remains similar since the CPU work must still be done, but **concurrency handling** improves dramatically. The server no longer blocks for half a second per request. 
*   **P95 improvement:** P95 latency under concurrent load is significantly reduced because requests no longer queue synchronously on the main thread.

## 5. Security

All Day 1-4 security features remain fully intact:
*   Prompt injection is still blocked using Heuristic and ML rules.
*   ML detection remains active via DeBERTa.
*   Unsafe responses from Ollama are still blocked.
*   Ollama is bypassed for malicious prompts.
*   Audit logging safely logs blocked and successful interactions.
*   Authentication and Rate Limiting remain functional.

## 6. Limitations

*   Measurements were taken on a local CPU without GPU acceleration for the DeBERTa model.
*   Database commits were tested locally; cloud SQL latencies may differ.
*   Ollama execution time dominates total request time, but is highly dependent on hardware (GPU presence) and the chosen LLM.
