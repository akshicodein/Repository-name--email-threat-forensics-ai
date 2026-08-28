"""
backend/detection/scoring.py

Explainable, rule-based technical risk scoring.

This module looks at the FORENSIC evidence (auth results, sender/reply-to,
domains, URLs) that Member 1's module extracts from the .eml file and turns
it into a transparent, additive risk score with a full breakdown of *why*
each point was awarded.

Design principle (per team spec): never emit a random/opaque score. Every
point on the scale must be traceable to a concrete indicator.

This module deliberately does NOT look at email body/subject language -
that's nlp.py's job. scoring.py is "what the headers/infrastructure say",
nlp.py is "what the words say". classifier.py combines both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Weights table - the single source of truth for technical scoring.
# Keep this centralised so the score is always explainable and reproducible.
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, int] = {
    "DMARC_FAIL": 25,
    "DKIM_FAIL": 12,
    "SPF_FAIL": 12,
    "REPLY_TO_MISMATCH": 20,
    "LOOKALIKE_DOMAIN": 18,
    "SUSPICIOUS_TLD": 8,
    "IP_LITERAL_URL": 12,
    "SUSPICIOUS_URL_KEYWORDS": 10,
    "URL_DOMAIN_MISMATCH_FROM_DOMAIN": 8,
    "SHORTENED_URL": 6,
    "NEWLY_LOOKING_RANDOM_DOMAIN": 10,
    "DISPLAY_NAME_SENDER_MISMATCH": 10,
    "FREEMAIL_FOR_EXEC": 8,
    "ATTACHMENT_RISK": 10,
    "MULTIPLE_RECEIVED_HOPS_ANOMALY": 6,
}

# A handful of common brand/company tokens used only to help spot lookalike
# domains in a demo-safe, generic way. Real deployments would use Member 1's
# "expected domain" evidence and/or a real brand-monitoring feed.
COMMON_BRAND_HINTS = [
    "paypal", "microsoft", "google", "apple", "amazon", "bank",
    "office365", "outlook", "docusign", "irs", "netflix",
]

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "work",
    "support", "loan", "men", "kim", "country",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "signin", "webscr", "password", "reset",
]


@dataclass
class ScoreReason:
    indicator: str
    points: int
    detail: str


@dataclass
class TechnicalScoreResult:
    score: int
    breakdown: list[ScoreReason] = field(default_factory=list)
    raw_indicators: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "breakdown": [
                {"indicator": r.indicator, "points": r.points, "detail": r.detail}
                for r in self.breakdown
            ],
        }


def _domain_of_email(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.strip().lower().split("@")[-1].strip(">").strip()


def _levenshtein(a: str, b: str) -> int:
    """Small dependency-free edit distance, used for lookalike-domain checks."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


_LEET_MAP = str.maketrans({"0": "o", "1": "l"})


def _is_lookalike_domain(domain: str, expected_domain: str | None) -> tuple[bool, str]:
    """Cheap heuristic lookalike-domain detector.

    Checks against an explicitly supplied "expected domain" (best signal,
    normally supplied by Member 1 / org config) and, failing that, against a
    generic list of well-known brand tokens (for demo purposes only).
    """
    if not domain:
        return False, ""

    core = domain.split(".")[0]
    normalized_core = core.translate(_LEET_MAP)

    if expected_domain and expected_domain.lower() != domain.lower():
        expected_core = expected_domain.split(".")[0]
        dist = _levenshtein(core, expected_core)
        # small edit distance relative to name length => likely lookalike
        if 0 < dist <= max(2, len(expected_core) // 4):
            return True, f"'{domain}' closely resembles expected domain '{expected_domain}'"
        if expected_core in core and core != expected_core:
            return True, f"'{domain}' embeds expected domain token '{expected_core}'"

    for brand in COMMON_BRAND_HINTS:
        if brand in normalized_core and normalized_core != brand:
            return True, f"'{domain}' embeds brand-like token '{brand}' (possibly with character substitution) but is not '{brand}.com'"

    return False, ""


def score_technical_indicators(
    forensic: dict[str, Any],
) -> TechnicalScoreResult:
    """Compute the explainable technical risk score from forensic evidence.

    `forensic` follows Member 1's forensic JSON contract (mock-compatible
    keys: sender, reply_to, spf, dkim, dmarc, urls, domains, display_name,
    expected_domain, attachments).
    """
    reasons: list[ScoreReason] = []
    indicators: dict[str, Any] = {}

    sender = forensic.get("sender") or forensic.get("from") or ""
    reply_to = forensic.get("reply_to") or ""
    display_name = forensic.get("display_name") or ""
    expected_domain = (forensic.get("expected_domain") or "").lower() or None

    sender_domain = _domain_of_email(sender)
    reply_domain = _domain_of_email(reply_to)

    spf = str(forensic.get("spf", "")).lower()
    dkim = str(forensic.get("dkim", "")).lower()
    dmarc = str(forensic.get("dmarc", "")).lower()

    # --- Authentication results -------------------------------------------------
    if dmarc == "fail":
        reasons.append(ScoreReason("DMARC_FAIL", WEIGHTS["DMARC_FAIL"], "DMARC alignment failed"))
    if dkim == "fail":
        reasons.append(ScoreReason("DKIM_FAIL", WEIGHTS["DKIM_FAIL"], "DKIM signature failed/missing"))
    if spf == "fail":
        reasons.append(ScoreReason("SPF_FAIL", WEIGHTS["SPF_FAIL"], "SPF check failed"))

    # --- Reply-To mismatch -------------------------------------------------------
    if reply_domain and sender_domain and reply_domain != sender_domain:
        reasons.append(ScoreReason(
            "REPLY_TO_MISMATCH", WEIGHTS["REPLY_TO_MISMATCH"],
            f"Reply-To domain '{reply_domain}' differs from sender domain '{sender_domain}'",
        ))
        indicators["reply_to_mismatch"] = True
    else:
        indicators["reply_to_mismatch"] = False

    # --- Display name / sender local-part vs actual sender address -----------------
    title_words = {"ceo", "cfo", "coo", "president", "director", "manager", "hr", "finance", "office"}
    sender_local = sender.split("@")[0].lower() if "@" in sender else ""

    looks_like_exec = False
    if display_name:
        # crude "looks like a person/exec name" heuristic (title word or "First Last" shape)
        looks_like_person = bool(re.match(r"^[A-Z][a-z]+(\s[A-Z][a-z]+)+$", display_name.strip()))
        looks_like_exec = any(w in display_name.lower() for w in title_words) or looks_like_person

    # Also treat an exec-styled sender local-part (e.g. "ceo@fake-company.com")
    # as an executive-style address signal, even with no display name at all.
    if any(w in sender_local for w in title_words):
        looks_like_exec = True

    if display_name and looks_like_exec:
        freemail = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}
        if sender_domain in freemail:
            reasons.append(ScoreReason(
                "FREEMAIL_FOR_EXEC", WEIGHTS["FREEMAIL_FOR_EXEC"],
                f"Display name '{display_name}' looks like an executive/person but sends from free webmail '{sender_domain}'",
            ))
    indicators["person_or_exec_display_name"] = looks_like_exec

    # --- Lookalike domain ---------------------------------------------------------
    for dom in forensic.get("domains") or ([sender_domain] if sender_domain else []):
        if not dom:
            continue
        is_lookalike, detail = _is_lookalike_domain(dom, expected_domain)
        if is_lookalike:
            reasons.append(ScoreReason("LOOKALIKE_DOMAIN", WEIGHTS["LOOKALIKE_DOMAIN"], detail))
            indicators["lookalike_domain"] = dom
            break

    # --- Suspicious TLD -------------------------------------------------------------
    for dom in forensic.get("domains") or []:
        tld = dom.split(".")[-1].lower() if dom and "." in dom else ""
        if tld in SUSPICIOUS_TLDS:
            reasons.append(ScoreReason(
                "SUSPICIOUS_TLD", WEIGHTS["SUSPICIOUS_TLD"], f"Domain '{dom}' uses a high-abuse TLD '.{tld}'",
            ))
            break

    # --- URL analysis -----------------------------------------------------------
    urls = forensic.get("urls") or []
    url_flags = {"ip_literal": False, "keyword": False, "shortener": False, "mismatch": False}
    for url in urls:
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            url_flags["ip_literal"] = True

        if any(kw in url.lower() for kw in SUSPICIOUS_URL_KEYWORDS):
            url_flags["keyword"] = True

        if host in URL_SHORTENERS:
            url_flags["shortener"] = True

        if sender_domain and host and sender_domain not in host and host not in sender_domain:
            url_flags["mismatch"] = True

    if url_flags["ip_literal"]:
        reasons.append(ScoreReason("IP_LITERAL_URL", WEIGHTS["IP_LITERAL_URL"], "Email contains a raw IP-address URL"))
    if url_flags["keyword"]:
        reasons.append(ScoreReason(
            "SUSPICIOUS_URL_KEYWORDS", WEIGHTS["SUSPICIOUS_URL_KEYWORDS"],
            "URL path/host contains credential-harvesting keywords (login/verify/secure/...)",
        ))
    if url_flags["shortener"]:
        reasons.append(ScoreReason("SHORTENED_URL", WEIGHTS["SHORTENED_URL"], "Email uses a URL shortener, hiding the real destination"))
    if url_flags["mismatch"] and urls:
        reasons.append(ScoreReason(
            "URL_DOMAIN_MISMATCH_FROM_DOMAIN", WEIGHTS["URL_DOMAIN_MISMATCH_FROM_DOMAIN"],
            "Linked URL host does not match the sender's domain",
        ))

    # --- Attachments (if Member 1 supplies attachment metadata) -----------------
    attachments = forensic.get("attachments") or []
    risky_ext = {".exe", ".scr", ".js", ".vbs", ".jar", ".hta", ".bat", ".ps1", ".iso", ".zip"}
    for att in attachments:
        name = att.get("name", "") if isinstance(att, dict) else str(att)
        if any(name.lower().endswith(ext) for ext in risky_ext):
            reasons.append(ScoreReason(
                "ATTACHMENT_RISK", WEIGHTS["ATTACHMENT_RISK"],
                f"Attachment '{name}' has a high-risk executable/archive extension",
            ))
            break

    total = min(100, sum(r.points for r in reasons))

    indicators.setdefault("lookalike_domain", False)
    fired = {r.indicator for r in reasons}
    indicators["suspicious_tld"] = "SUSPICIOUS_TLD" in fired
    indicators["freemail_for_exec"] = "FREEMAIL_FOR_EXEC" in fired
    indicators["attachment_risk"] = "ATTACHMENT_RISK" in fired

    indicators.update({
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "sender_domain": sender_domain, "reply_domain": reply_domain,
        "display_name": display_name,
        "url_flags": url_flags,
    })

    return TechnicalScoreResult(score=total, breakdown=reasons, raw_indicators=indicators)


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
