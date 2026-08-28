"""
backend/detection/attack_dna.py

Attack DNA: a compact, human-readable fingerprint derived from a normalized
feature vector describing the email's behaviour (headers/auth, domain/URL
characteristics, and social-engineering language patterns).

Design goals (per team spec):
  1. NOT a random hash - every byte of the DNA is derived from a meaningful,
     named feature group so a teammate could explain "why does this DNA
     start with A7?".
  2. Similar emails -> similar DNA. We achieve this by (a) keeping the full
     16-dimension feature vector as the "features" field for precise
     comparison, and (b) deriving each DNA byte from the *average* of a
     small feature group, so nearby feature vectors round to nearby bytes.
  3. Similarity is explicitly framed as "potentially related", never as
     proof of common authorship.

This module exposes:
  - build_feature_vector(...)      -> ordered dict[str, float] in [0, 1]
  - generate_attack_dna(vector)    -> "A7-F3-C9-21-88" style string
  - compare_with_history(vector)   -> ranked list of similar historical cases
  - register_case(...)             -> persist a new case into the (mock)
                                       historical store, so the demo can grow
                                       its own "memory" as emails are analyzed
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HISTORY_FILE = os.path.join(DATA_DIR, "historical_cases.json")

# ---------------------------------------------------------------------------
# Feature vector definition
# ---------------------------------------------------------------------------
# Fixed order matters: the DNA byte-groups below are computed positionally
# from this list, and cosine similarity requires consistent dimension order
# across all stored/compared cases.

FEATURE_ORDER: list[str] = [
    # Header / authentication behaviour
    "dmarc_fail", "dkim_fail", "spf_fail", "reply_to_mismatch",
    # Domain / URL / infrastructure characteristics
    "lookalike_domain", "suspicious_tld", "ip_literal_url",
    "suspicious_url_keywords", "url_domain_mismatch",
    # Urgency / pressure language
    "urgency", "artificial_deadline", "suspicious_cta",
    # Broader social-engineering language
    "fear_threat", "authority_pressure", "confidentiality_pressure",
    "account_verification",
    # Financial / credential / impersonation intent
    "financial_manipulation", "credential_request", "executive_impersonation",
]

# Which byte (0-4) of the 5-byte DNA each feature contributes to. Grouped so
# each byte has a clear semantic meaning for demo storytelling.
DNA_BYTE_GROUPS: list[list[str]] = [
    ["dmarc_fail", "dkim_fail", "spf_fail", "reply_to_mismatch"],                      # byte 0: header/auth
    ["lookalike_domain", "suspicious_tld", "ip_literal_url",
     "suspicious_url_keywords", "url_domain_mismatch"],                                 # byte 1: domain/URL
    ["urgency", "artificial_deadline", "suspicious_cta"],                               # byte 2: urgency/pressure
    ["fear_threat", "authority_pressure", "confidentiality_pressure",
     "account_verification"],                                                          # byte 3: social engineering
    ["financial_manipulation", "credential_request", "executive_impersonation"],        # byte 4: intent
]

DNA_BYTE_LABELS = ["HEADER_AUTH", "DOMAIN_URL", "URGENCY", "SOCIAL_ENG", "INTENT"]


def build_feature_vector(
    technical_indicators: dict[str, Any],
    url_flags: dict[str, bool],
    nlp_raw_scores: dict[str, float],
    executive_impersonation_score: float,
) -> dict[str, float]:
    """Assemble the normalized (0..1) feature vector used for both the DNA
    fingerprint and the similarity comparison.
    """
    vec = {
        "dmarc_fail": 1.0 if technical_indicators.get("dmarc") == "fail" else 0.0,
        "dkim_fail": 1.0 if technical_indicators.get("dkim") == "fail" else 0.0,
        "spf_fail": 1.0 if technical_indicators.get("spf") == "fail" else 0.0,
        "reply_to_mismatch": 1.0 if technical_indicators.get("reply_to_mismatch") else 0.0,
        "lookalike_domain": 1.0 if technical_indicators.get("lookalike_domain") else 0.0,
        "suspicious_tld": 1.0 if technical_indicators.get("suspicious_tld") else 0.0,
        "ip_literal_url": 1.0 if url_flags.get("ip_literal") else 0.0,
        "suspicious_url_keywords": 1.0 if url_flags.get("keyword") else 0.0,
        "url_domain_mismatch": 1.0 if url_flags.get("mismatch") else 0.0,
        "urgency": nlp_raw_scores.get("urgency", 0.0),
        "artificial_deadline": nlp_raw_scores.get("artificial_deadline", 0.0),
        "suspicious_cta": nlp_raw_scores.get("suspicious_cta", 0.0),
        "fear_threat": nlp_raw_scores.get("fear_threat", 0.0),
        "authority_pressure": nlp_raw_scores.get("authority_pressure", 0.0),
        "confidentiality_pressure": nlp_raw_scores.get("confidentiality_pressure", 0.0),
        "account_verification": nlp_raw_scores.get("account_verification", 0.0),
        "financial_manipulation": nlp_raw_scores.get("financial_manipulation", 0.0),
        "credential_request": nlp_raw_scores.get("credential_request", 0.0),
        "executive_impersonation": executive_impersonation_score,
    }
    # Guarantee stable, complete ordering regardless of dict insertion order.
    return {k: round(float(vec.get(k, 0.0)), 3) for k in FEATURE_ORDER}


def generate_attack_dna(vector: dict[str, float]) -> str:
    """Derive a 5-byte hex fingerprint (e.g. 'A7-F3-C9-21-88') from the
    feature vector. Each byte is the quantized average of a named feature
    group, so similar vectors naturally produce similar/identical bytes.
    """
    bytes_out = []
    for group in DNA_BYTE_GROUPS:
        vals = [vector.get(f, 0.0) for f in group]
        avg = sum(vals) / len(vals) if vals else 0.0
        byte_val = min(255, round(avg * 255))
        bytes_out.append(byte_val)
    return "-".join(f"{b:02X}" for b in bytes_out)


def dna_byte_breakdown(vector: dict[str, float]) -> list[dict[str, Any]]:
    """Human-readable explanation of what each DNA byte represents - useful
    for the dashboard/demo ("why does this fingerprint start with A7?")."""
    out = []
    dna = generate_attack_dna(vector)
    parts = dna.split("-")
    for label, group, part in zip(DNA_BYTE_LABELS, DNA_BYTE_GROUPS, parts):
        vals = [vector.get(f, 0.0) for f in group]
        avg = sum(vals) / len(vals) if vals else 0.0
        out.append({
            "byte": part,
            "category": label,
            "contributing_features": group,
            "group_average": round(avg, 3),
        })
    return out


def cosine_similarity(v1: dict[str, float], v2: dict[str, float]) -> float:
    keys = FEATURE_ORDER
    a = [v1.get(k, 0.0) for k in keys]
    b = [v2.get(k, 0.0) for k in keys]
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Historical case store (mock "threat memory" for standalone dev/demo use).
# Member 3's Threat Memory / Campaign Correlation module is the real, richer
# home for this in the integrated system - this local store just lets
# Member 2 develop and demo Attack-DNA similarity independently.
# ---------------------------------------------------------------------------

@dataclass
class HistoricalCase:
    case_id: str
    attack_dna: str
    classification: str
    features: dict[str, float]
    summary: str


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def load_history() -> list[HistoricalCase]:
    _ensure_data_dir()
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [HistoricalCase(**item) for item in raw]


def save_history(cases: list[HistoricalCase]) -> None:
    _ensure_data_dir()
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump([c.__dict__ for c in cases], f, indent=2)


def register_case(case_id: str, attack_dna: str, classification: str,
                   features: dict[str, float], summary: str) -> None:
    """Append a new case to the historical store so future analyses can be
    compared against it. Used by the demo to build up "memory" over a
    session; Member 3's real system will own persistence long-term.
    """
    cases = load_history()
    cases.append(HistoricalCase(case_id, attack_dna, classification, features, summary))
    save_history(cases)


def compare_with_history(
    vector: dict[str, float],
    top_n: int = 3,
    min_similarity: float = 0.55,
) -> list[dict[str, Any]]:
    """Compare the current feature vector against stored historical cases.

    Returns a ranked list of matches with careful, non-attributive wording.
    Similarity is a mathematical property of the feature vectors - it never
    constitutes proof of a shared attacker.
    """
    history = load_history()
    results = []
    for case in history:
        sim = cosine_similarity(vector, case.features)
        if sim >= min_similarity:
            results.append({
                "case_id": case.case_id,
                "attack_dna": case.attack_dna,
                "classification": case.classification,
                "similarity": round(sim * 100, 1),
                "note": _similarity_note(sim),
                "summary": case.summary,
            })
    results.sort(key=lambda r: r["similarity"], reverse=True)
    return results[:top_n]


def _similarity_note(sim: float) -> str:
    if sim >= 0.9:
        return "High similarity with previous case - potentially related activity."
    if sim >= 0.75:
        return "Moderate-to-high similarity - possible campaign relationship."
    return "Some overlapping characteristics with previous case - worth reviewing."
