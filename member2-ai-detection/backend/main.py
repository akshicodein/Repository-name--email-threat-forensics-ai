"""
backend/main.py

Minimal FastAPI app exposing the detection module's POST /analyze endpoint.

This is Member 2's standalone entry point for independent development/demo.
If the team's shared main API architecture (owned collectively / by another
member) already defines app-level routing, mount `detection_router` there
instead of running this file directly - see the `include_router` example at
the bottom of this file.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.detection.classifier import analyze_email

# ---------------------------------------------------------------------------
# Request schema - deliberately permissive/mock-compatible. Once Member 1's
# real forensic JSON schema is finalized, this model should be tightened to
# match it exactly (field names must stay compatible per the team contract).
# ---------------------------------------------------------------------------


class AttachmentInfo(BaseModel):
    name: str
    size_bytes: Optional[int] = None


class AnalyzeRequest(BaseModel):
    subject: str = ""
    body: str = ""
    sender: str = Field(default="", description="From address")
    reply_to: str = ""
    display_name: str = ""
    expected_domain: Optional[str] = None
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)

    # Free-form escape hatch: if Member 1's forensic JSON includes extra
    # fields we don't explicitly model yet, they still pass through.
    model_config = {"extra": "allow"}


class AnalyzeResponse(BaseModel):
    classification: str
    risk_score: int
    risk_level: str
    scores: dict[str, float]
    indicators: list[str]
    social_engineering: dict[str, str]
    attack_dna: str
    features: dict[str, float]
    dna_similarity: list[dict[str, Any]]

    # additive/extra fields - safe for consumers to ignore
    scores_extended: dict[str, float]
    risk_breakdown: list[dict[str, Any]]
    social_engineering_detail: dict[str, Any]
    impersonation_analysis: dict[str, Any]
    attack_dna_breakdown: list[dict[str, Any]]
    summary: str

    model_config = {"extra": "allow"}


detection_router = APIRouter(tags=["detection"])


@detection_router.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, remember_case: bool = False) -> dict[str, Any]:
    """Analyze a single email (forensic JSON + content) and return the
    detection JSON contract (classification, risk, indicators, Attack DNA,
    and historical similarity).

    `remember_case`: if true, stores this case's Attack DNA/features into
    the local mock historical store so future analyses can be compared
    against it (handy for demoing campaign correlation in a single session).
    """
    return analyze_email(payload.model_dump(), register_history=remember_case)


@detection_router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "module": "detection"}


# ---------------------------------------------------------------------------
# Standalone app (for `uvicorn backend.main:app --reload` during dev/demo).
# If the team merges into one shared FastAPI app, replace this block with:
#     from backend.detection.main import detection_router
#     app.include_router(detection_router)
# in the shared main.py instead.
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Email Threat Forensics AI - Detection Module",
    description="AI Threat Detection, Risk Scoring, NLP/Social-Engineering Analysis & Attack DNA (Member 2)",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detection_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Email Threat Forensics AI - detection module. POST /analyze to use it."}
