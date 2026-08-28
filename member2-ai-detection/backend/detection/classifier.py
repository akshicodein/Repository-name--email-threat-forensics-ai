"""
backend/detection/classifier.py

Orchestrator: combines scoring.py (technical/header evidence) + nlp.py
(social-engineering language evidence) + attack_dna.py (fingerprint +
historical similarity) into the single JSON output contract that Member 3
and Member 4 consume.

>>> from backend.detection.classifier import analyze_email
>>> analyze_email(mock_forensic_json)
{...}  # see OUTPUT CONTRACT in the project spec / docs/detection-module.md

NOTE ON SCOPE: This module never claims attribution or certainty. Per team
rules, technical/NLP findings are phrased as indicators and risk assessment,
not proof.
"""

from __future__ import annotations

import re
from typing import Any

from . import attack_dna as dna
from . import scoring
from .nlp import analyze_text

CLASSIFICATIONS = [
    "LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC", "IMPERSONATION",
    "CREDENTIAL_THEFT", "FINANCIAL_FRAUD", "MALWARE",
]

# Points added to the base technical score for language-level signals.
# Mirrors the additive, explainable style requested for the technical score.
NLP_POINT_WEIGHTS: dict[str, int] = {
    "urgency": 10,
    "financial_manipulation": 12,
    "credential_request": 12,
    "fear_threat": 8,
    "authority_pressure": 8,
    "confidentiality_pressure": 6,
    "artificial_deadline": 6,
    "suspicious_cta": 8,
    "account_verification": 6,
}
LABEL_MULTIPLIER = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, "NONE": 0.0}

INDICATOR_LABELS: dict[str, str] = {
    "DMARC_FAIL": "DMARC failure",
    "DKIM_FAIL": "DKIM failure",
    "SPF_FAIL": "SPF failure",
    "REPLY_TO_MISMATCH": "Reply-To mismatch",
    "LOOKALIKE_DOMAIN": "Suspicious/lookalike domain",
    "SUSPICIOUS_TLD": "High-abuse domain TLD",
    "IP_LITERAL_URL": "Suspicious URL (raw IP address)",
    "SUSPICIOUS_URL_KEYWORDS": "Suspicious URL",
    "URL_DOMAIN_MISMATCH_FROM_DOMAIN": "URL domain mismatch",
    "SHORTENED_URL": "Shortened/obfuscated URL",
    "FREEMAIL_FOR_EXEC": "Executive-style sender using free webmail",
    "ATTACHMENT_RISK": "Risky attachment",
}

NLP_INDICATOR_LABELS: dict[str, str] = {
    "urgency": "Urgency language",
    "fear_threat": "Fear/threat language",
    "authority_pressure": "Authority pressure",
    "financial_manipulation": "Financial request",
    "credential_request": "Credential request",
    "account_verification": "Account verification request",
    "confidentiality_pressure": "Confidentiality pressure",
    "artificial_deadline": "Artificial deadline",
    "suspicious_cta": "Suspicious call-to-action",
}


def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _executive_impersonation_score(
    technical_indicators: dict[str, Any],
    nlp_result,
) -> tuple[float, bool]:
    """Combine address-based + language-based executive impersonation
    signals into a single 0..1 score, plus a boolean "suspected" flag.
    """
    # A lookalike domain is only a strong *executive*-impersonation signal
    # when paired with a person/exec-styled display name (e.g. "CEO John").
    # Otherwise it's more likely generic brand/vendor phishing (e.g. a fake
    # "Netflix" or "PayPal" notice), which PHISHING/CREDENTIAL_THEFT already
    # capture without needing to also claim executive impersonation.
    person_or_exec = bool(technical_indicators.get("person_or_exec_display_name"))

    address_signal = 0.0
    if technical_indicators.get("lookalike_domain"):
        address_signal = max(address_signal, 0.85 if person_or_exec else 0.3)
    if technical_indicators.get("freemail_for_exec"):
        address_signal = max(address_signal, 0.7)
    if technical_indicators.get("reply_to_mismatch") and person_or_exec:
        address_signal = max(address_signal, 0.4)

    language_signal = 0.0
    if nlp_result.exec_impersonation_language:
        language_signal = min(1.0, 0.5 + 0.15 * len(nlp_result.exec_impersonation_matches))
    authority = nlp_result.dimensions.get("authority_pressure")
    if authority:
        language_signal = max(language_signal, authority.raw_score * 0.6)

    score = _clip01(max(address_signal, language_signal, 0.5 * (address_signal + language_signal)))
    suspected = score >= 0.5 and (address_signal > 0 or language_signal > 0)
    return round(score, 2), suspected


def _category_scores(
    technical_indicators: dict[str, Any],
    url_flags: dict[str, bool],
    nlp_raw: dict[str, float],
    exec_score: float,
) -> dict[str, float]:
    dmarc_fail = 1.0 if technical_indicators.get("dmarc") == "fail" else 0.0
    dkim_fail = 1.0 if technical_indicators.get("dkim") == "fail" else 0.0
    spf_fail = 1.0 if technical_indicators.get("spf") == "fail" else 0.0
    auth_fail_avg = (dmarc_fail + dkim_fail + spf_fail) / 3
    lookalike = 1.0 if technical_indicators.get("lookalike_domain") else 0.0
    reply_mismatch = 1.0 if technical_indicators.get("reply_to_mismatch") else 0.0
    url_bad = 1.0 if (url_flags.get("ip_literal") or url_flags.get("keyword") or url_flags.get("shortener")) else 0.0
    url_mismatch = 1.0 if url_flags.get("mismatch") else 0.0
    attachment_risk = 1.0 if technical_indicators.get("attachment_risk") else 0.0
    freemail_exec = 1.0 if technical_indicators.get("freemail_for_exec") else 0.0

    phishing = _clip01(
        0.25 * nlp_raw.get("credential_request", 0)
        + 0.20 * nlp_raw.get("suspicious_cta", 0)
        + 0.20 * url_bad
        + 0.15 * lookalike
        + 0.10 * auth_fail_avg
        + 0.10 * url_mismatch
    )

    bec = _clip01(
        0.30 * nlp_raw.get("financial_manipulation", 0)
        + 0.25 * exec_score
        + 0.20 * nlp_raw.get("authority_pressure", 0)
        + 0.15 * reply_mismatch
        + 0.10 * nlp_raw.get("urgency", 0)
    )

    impersonation = _clip01(
        0.40 * exec_score
        + 0.25 * lookalike
        + 0.20 * freemail_exec
        + 0.15 * reply_mismatch
    )

    credential_theft = _clip01(
        0.35 * nlp_raw.get("credential_request", 0)
        + 0.25 * nlp_raw.get("account_verification", 0)
        + 0.20 * nlp_raw.get("suspicious_cta", 0)
        + 0.20 * url_bad
    )

    financial_fraud = _clip01(
        0.35 * nlp_raw.get("financial_manipulation", 0)
        + 0.25 * nlp_raw.get("confidentiality_pressure", 0)
        + 0.20 * nlp_raw.get("urgency", 0)
        + 0.20 * (1 - exec_score)
    ) if nlp_raw.get("financial_manipulation", 0) > 0 else 0.0

    malware = _clip01(0.65 * attachment_risk + 0.35 * nlp_raw.get("suspicious_cta", 0))

    return {
        "phishing": round(phishing, 2),
        "bec": round(bec, 2),
        "impersonation": round(impersonation, 2),
        "credential_theft": round(credential_theft, 2),
        "financial_fraud": round(financial_fraud, 2),
        "malware": round(malware, 2),
    }


# Priority order used to break near-ties between category scores - more
# specific / higher-severity categories win over generic "phishing".
CATEGORY_PRIORITY = ["malware", "bec", "impersonation", "credential_theft", "financial_fraud", "phishing"]
CATEGORY_TO_CLASSIFICATION = {
    "malware": "MALWARE",
    "bec": "BEC",
    "impersonation": "IMPERSONATION",
    "credential_theft": "CREDENTIAL_THEFT",
    "financial_fraud": "FINANCIAL_FRAUD",
    "phishing": "PHISHING",
}


def _decide_classification(risk_score: int, category_scores: dict[str, float]) -> str:
    best_cat = max(CATEGORY_PRIORITY, key=lambda c: (category_scores.get(c, 0), -CATEGORY_PRIORITY.index(c)))
    best_val = category_scores.get(best_cat, 0)

    # tie-break: any category within 0.05 of the best gets priority order applied
    contenders = [c for c in CATEGORY_PRIORITY if category_scores.get(c, 0) >= best_val - 0.05]
    for c in CATEGORY_PRIORITY:
        if c in contenders and category_scores.get(c, 0) == max(category_scores.get(x, 0) for x in contenders):
            best_cat = c
            break

    if risk_score < 20 and best_val < 0.30:
        return "LEGITIMATE"
    if best_val < 0.35:
        return "SUSPICIOUS"
    return CATEGORY_TO_CLASSIFICATION[best_cat]


def _build_indicators(
    tech_breakdown: list,
    nlp_result,
    exec_suspected: bool,
) -> list[str]:
    out: list[str] = []
    for reason in tech_breakdown:
        label = INDICATOR_LABELS.get(reason.indicator, reason.indicator)
        if label not in out:
            out.append(label)

    for dim_name, dim in nlp_result.dimensions.items():
        if dim.label in ("HIGH", "MEDIUM") and dim_name in NLP_INDICATOR_LABELS:
            label = NLP_INDICATOR_LABELS[dim_name]
            if label not in out:
                out.append(label)

    if exec_suspected and "Executive impersonation" not in out:
        out.append("Executive impersonation")

    return out


def _social_engineering_summary(nlp_result) -> dict[str, str]:
    keys = ["urgency", "authority_pressure", "financial_manipulation", "credential_request"]
    return {k: nlp_result.dimensions[k].label for k in keys if k in nlp_result.dimensions}


def _narrative_summary(classification: str, risk_score: int, risk_level: str, indicators: list[str]) -> str:
    top = ", ".join(indicators[:5]) if indicators else "no significant indicators"
    return (
        f"AI assessment indicates {risk_level} risk ({risk_score}/100). "
        f"Classified as {classification} based on: {top}. "
        f"This is investigative intelligence, not confirmed attribution."
    )


def analyze_email(payload: dict[str, Any], register_history: bool = False, case_id: str | None = None) -> dict[str, Any]:
    """Main entry point. `payload` is forensic evidence + email content,
    following the mock/forensic JSON contract described in the spec:

        subject, body, sender, reply_to, spf, dkim, dmarc, urls, domains,
        (optional) display_name, expected_domain, attachments

    Returns the standard detection JSON described in the OUTPUT CONTRACT.
    """
    subject = payload.get("subject", "")
    body = payload.get("body", "")

    tech_result = scoring.score_technical_indicators(payload)
    nlp_result = analyze_text(subject, body)

    exec_score, exec_suspected = _executive_impersonation_score(tech_result.raw_indicators, nlp_result)

    nlp_raw = nlp_result.raw_scores()
    url_flags = tech_result.raw_indicators.get("url_flags", {})

    category_scores = _category_scores(tech_result.raw_indicators, url_flags, nlp_raw, exec_score)

    # --- combined, explainable risk score (technical + language) -----------
    nlp_points = 0
    for dim_name, weight in NLP_POINT_WEIGHTS.items():
        dim = nlp_result.dimensions.get(dim_name)
        if dim:
            nlp_points += weight * LABEL_MULTIPLIER.get(dim.label, 0.0)
    if exec_suspected:
        nlp_points += 10

    risk_score = int(round(min(100, tech_result.score + nlp_points)))
    risk_level = scoring.risk_level_from_score(risk_score)

    classification = _decide_classification(risk_score, category_scores)
    indicators = _build_indicators(tech_result.breakdown, nlp_result, exec_suspected)
    social_engineering = _social_engineering_summary(nlp_result)

    feature_vector = dna.build_feature_vector(
        technical_indicators=tech_result.raw_indicators,
        url_flags=url_flags,
        nlp_raw_scores=nlp_raw,
        executive_impersonation_score=exec_score,
    )
    attack_dna = dna.generate_attack_dna(feature_vector)
    dna_similarity = dna.compare_with_history(feature_vector)

    result: dict[str, Any] = {
        # --- required contract fields ---------------------------------
        "classification": classification,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scores": {
            "phishing": category_scores["phishing"],
            "bec": category_scores["bec"],
            "impersonation": category_scores["impersonation"],
            "credential_theft": category_scores["credential_theft"],
            "financial_fraud": category_scores["financial_fraud"],
        },
        "indicators": indicators,
        "social_engineering": social_engineering,
        "attack_dna": attack_dna,
        "features": feature_vector,
        "dna_similarity": dna_similarity,

        # --- additive, non-breaking extras (safe to ignore) -------------
        "scores_extended": category_scores,  # includes "malware" too
        "risk_breakdown": tech_result.as_dict()["breakdown"],
        "social_engineering_detail": {
            name: {"label": d.label, "raw_score": d.raw_score, "matches": d.matches}
            for name, d in nlp_result.dimensions.items()
        },
        "impersonation_analysis": {
            "display_name": tech_result.raw_indicators.get("display_name"),
            "actual_sender_domain": tech_result.raw_indicators.get("sender_domain"),
            "expected_domain": (payload.get("expected_domain") or None),
            "executive_impersonation_score": exec_score,
            "executive_impersonation_suspected": exec_suspected,
        },
        "attack_dna_breakdown": dna.dna_byte_breakdown(feature_vector),
        "summary": _narrative_summary(classification, risk_score, risk_level, indicators),
    }

    if register_history:
        cid = case_id or f"CASE-{attack_dna.replace('-', '')[:6]}"
        dna.register_case(
            case_id=cid,
            attack_dna=attack_dna,
            classification=classification,
            features=feature_vector,
            summary=result["summary"],
        )

    return result
