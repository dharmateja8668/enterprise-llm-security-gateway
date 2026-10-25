"""
app/routes/pii.py
POST /pii/scan — Demo / diagnostic endpoint for PII detection (Week 2).

This endpoint allows direct testing of the Presidio PII detection
service without going through the full authenticated chat flow.

It is intentionally lightweight and requires no authentication so that
developers and QA can quickly verify detection behaviour.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import List, Optional

from app.services.pii_analyzer import analyze_pii, summarize_pii, PIIEntity

router = APIRouter(prefix="/pii", tags=["PII Detection"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PIIScanRequest(BaseModel):
    text: str = Field(..., description="The text to scan for PII.")
    language: str = Field(
        default="en",
        description="ISO-639-1 language code for NLP analysis.",
    )
    score_threshold: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score (0.0–1.0) to include a finding.",
    )


class PIIFinding(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    text_snippet: str


class PIIScanResponse(BaseModel):
    pii_detected: bool
    count: int
    entity_types: List[str]
    findings: List[PIIFinding]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=PIIScanResponse)
async def scan_for_pii(request: PIIScanRequest):
    """Scan the submitted text for PII entities.

    Returns detected entity types, positions, confidence scores, and
    matched snippets.  **No redaction or anonymization is performed.**
    """
    entities: List[PIIEntity] = analyze_pii(
        text=request.text,
        language=request.language,
        score_threshold=request.score_threshold,
    )

    summary = summarize_pii(entities)

    return PIIScanResponse(
        pii_detected=summary["pii_detected"],
        count=summary["count"],
        entity_types=summary["entity_types"],
        findings=[
            PIIFinding(
                entity_type=e.entity_type,
                start=e.start,
                end=e.end,
                score=e.score,
                text_snippet=e.text_snippet,
            )
            for e in entities
        ],
    )
