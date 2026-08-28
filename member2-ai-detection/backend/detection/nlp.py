"""
backend/detection/nlp.py

Lightweight, dependency-free NLP / social-engineering analysis.

For the hackathon MVP this is a transparent keyword + pattern based scorer
rather than a trained model - this keeps it fast, explainable, and usable
with zero training data. Each dimension below produces:

  - a 0.0-1.0 raw signal strength
  - a LOW / MEDIUM / HIGH label
  - the specific matched phrases (for explainability / demo storytelling)

classifier.py combines these signals with scoring.py's technical signals to
reach a final classification + Attack DNA feature vector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Keyword/pattern banks. Grouped by social-engineering dimension.
# Kept intentionally simple (word/phrase lists) so it's easy to extend live
# during the hackathon without touching scoring logic.
# ---------------------------------------------------------------------------

PATTERNS: dict[str, list[str]] = {
    "urgency": [
        r"\burgent\b", r"\bimmediately\b", r"\bas soon as possible\b", r"\basap\b",
        r"\bright away\b", r"\bwithout delay\b", r"\btime[- ]sensitive\b",
        r"\bact now\b", r"\bexpires? (today|soon|in)\b", r"\blast (chance|warning)\b",
    ],
    "fear_threat": [
        r"\bsuspend(ed|sion)?\b", r"\bclos(e|ed|ing) your account\b", r"\blegal action\b",
        r"\bpenalt(y|ies)\b", r"\bconsequences\b", r"\bterminat(e|ed|ion)\b",
        r"\bunauthoriz(ed|e) access\b", r"\bsecurity (alert|breach)\b",
    ],
    "authority_pressure": [
        r"\bceo\b", r"\bcfo\b", r"\bpresident\b", r"\bmanagement\b", r"\bboard\b",
        r"\bcompliance\b", r"\bdirect order\b", r"\bon behalf of\b", r"\bexecutive\b",
        r"\bthis is (a )?direct(ion|ive)\b",
    ],
    "financial_manipulation": [
        r"\bwire transfer\b", r"\btransfer (the )?(funds?|amount|money)\b", r"\binvoice\b",
        r"\bbank (account|details)\b", r"\bpayment\b", r"\bgift cards?\b",
        r"\brouting number\b", r"\bpayroll\b", r"\bswift\b", r"\biban\b",
        r"\bchange (of )?(bank|account) details\b", r"\bupdate.*(bank|payment) (details|information)\b",
    ],
    "credential_request": [
        r"\bpassword\b", r"\busername\b", r"\blogin credentials?\b", r"\bverify your (account|identity)\b",
        r"\bconfirm your (account|password|identity)\b", r"\bre-?enter your\b", r"\bmfa code\b",
        r"\bone[- ]time (passcode|code)\b", r"\bsecurity code\b",
    ],
    "account_verification": [
        r"\bverify (your )?account\b", r"\bconfirm (your )?(identity|details)\b",
        r"\bupdate (your )?(account|information|profile)\b", r"\breactivate\b",
        r"\bunlock your account\b",
    ],
    "confidentiality_pressure": [
        r"\bconfidential\b", r"\bdo not (tell|discuss|share|forward)\b", r"\bkeep this (between us|private|secret)\b",
        r"\bdon'?t (cc|copy|involve)\b", r"\bbetween (you and me|us)\b",
    ],
    "artificial_deadline": [
        r"\bwithin (the )?(next )?\d+\s*(hours?|minutes?|days?)\b", r"\bby (today|tomorrow|end of day|eod|cob)\b",
        r"\bbefore \d{1,2}(:\d{2})?\s*(am|pm)\b", r"\bdeadline\b",
    ],
    "suspicious_cta": [
        r"\bclick (here|below|this link)\b", r"\bdownload (the )?attachment\b", r"\bopen the attached\b",
        r"\bfollow this link\b", r"\bverify now\b", r"\blog in now\b",
    ],
}

# Executive-impersonation phrases used as an extra language-level signal on
# top of the address-based check done in classifier.py.
EXEC_IMPERSONATION_PHRASES = [
    r"\bi'?m (currently )?in a meeting\b", r"\bcan'?t talk right now\b",
    r"\bi need you to handle this quietly\b", r"\bthis is (the )?ceo\b",
    r"\breach me (only )?(by|on) email\b", r"\bunavailable by phone\b",
]


@dataclass
class DimensionResult:
    raw_score: float
    label: str
    matches: list[str] = field(default_factory=list)


@dataclass
class NLPResult:
    dimensions: dict[str, DimensionResult]
    exec_impersonation_language: bool
    exec_impersonation_matches: list[str]

    def social_engineering_dict(self) -> dict[str, str]:
        return {name: d.label for name, d in self.dimensions.items()}

    def raw_scores(self) -> dict[str, float]:
        return {name: d.raw_score for name, d in self.dimensions.items()}

    def all_matches(self) -> dict[str, list[str]]:
        return {name: d.matches for name, d in self.dimensions.items() if d.matches}


def _label_from_score(score: float) -> str:
    if score >= 0.66:
        return "HIGH"
    if score >= 0.33:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _scan(text: str, patterns: list[str]) -> list[str]:
    found = []
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            found.append(m.group(0))
    return found


def analyze_text(subject: str | None, body: str | None) -> NLPResult:
    """Run the full social-engineering language analysis on subject+body."""
    text = f"{subject or ''}\n{body or ''}"

    dimensions: dict[str, DimensionResult] = {}
    for dim, patterns in PATTERNS.items():
        matches = _scan(text, patterns)
        # Diminishing returns per extra match keeps score bounded 0..1
        raw = min(1.0, 0.0 if not matches else 0.35 + 0.2 * (len(matches) - 1) + 0.15)
        raw = round(min(raw, 1.0), 2)
        dimensions[dim] = DimensionResult(raw_score=raw, label=_label_from_score(raw), matches=matches)

    exec_matches = _scan(text, EXEC_IMPERSONATION_PHRASES)

    return NLPResult(
        dimensions=dimensions,
        exec_impersonation_language=bool(exec_matches),
        exec_impersonation_matches=exec_matches,
    )
