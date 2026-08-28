import pytest

from backend.detection.classifier import analyze_email
from tests.detection.mock_data import (
    BEC_EMAILS, FRAUD_EMAILS, IMPERSONATION_EMAILS, LEGITIMATE_EMAILS,
    MALWARE_EMAILS, PHISHING_EMAILS,
)

REQUIRED_KEYS = {
    "classification", "risk_score", "risk_level", "scores", "indicators",
    "social_engineering", "attack_dna", "features", "dna_similarity",
}


@pytest.mark.parametrize("email", LEGITIMATE_EMAILS)
def test_legitimate_emails_score_low(email):
    result = analyze_email(email)
    assert REQUIRED_KEYS.issubset(result.keys())
    assert result["classification"] == "LEGITIMATE"
    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 20


@pytest.mark.parametrize("email", PHISHING_EMAILS)
def test_phishing_emails_flagged_high_risk(email):
    result = analyze_email(email)
    assert result["classification"] in ("PHISHING", "CREDENTIAL_THEFT", "SUSPICIOUS")
    assert result["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")
    assert result["risk_score"] > 30
    assert len(result["indicators"]) > 0


@pytest.mark.parametrize("email", BEC_EMAILS)
def test_bec_emails_classified_correctly(email):
    result = analyze_email(email)
    assert result["classification"] in ("BEC", "IMPERSONATION", "FINANCIAL_FRAUD")
    assert result["risk_score"] > 40
    assert result["scores"]["bec"] > 0.3


@pytest.mark.parametrize("email", IMPERSONATION_EMAILS)
def test_impersonation_emails_flag_executive_impersonation(email):
    result = analyze_email(email)
    assert result["impersonation_analysis"]["executive_impersonation_score"] > 0
    assert result["classification"] != "LEGITIMATE"


@pytest.mark.parametrize("email", FRAUD_EMAILS)
def test_fraud_emails_are_not_legitimate(email):
    result = analyze_email(email)
    assert result["classification"] != "LEGITIMATE"
    assert result["risk_score"] > 20


@pytest.mark.parametrize("email", MALWARE_EMAILS)
def test_malware_email_flags_attachment_risk(email):
    result = analyze_email(email)
    assert "Risky attachment" in result["indicators"]
    assert result["classification"] != "LEGITIMATE"


def test_bec_success_criteria_example_from_spec():
    """Mirrors the exact example from the project spec's SUCCESS CRITERIA."""
    email = {
        "subject": "URGENT PAYMENT REQUIRED",
        "body": "Please transfer the amount immediately...",
        "sender": "ceo@fake-company.com",
        "reply_to": "random@gmail.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["https://fake-login.example"],
        "domains": ["fake-company.com"],
    }
    result = analyze_email(email)

    assert result["classification"] in ("BEC", "IMPERSONATION")
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert "Reply-To mismatch" in result["indicators"]
    assert result["attack_dna"].count("-") == 4
    assert all(len(part) == 2 for part in result["attack_dna"].split("-"))


def test_output_never_claims_confirmed_attribution():
    email = BEC_EMAILS[0]
    result = analyze_email(email)
    forbidden_phrases = ["confirmed same attacker", "proves", "guaranteed attribution", "definitely sent by"]
    summary_lower = result["summary"].lower()
    for phrase in forbidden_phrases:
        assert phrase not in summary_lower
    for match in result["dna_similarity"]:
        assert "confirm" not in match["note"].lower()
        assert "proves" not in match["note"].lower()


def test_risk_score_bounded_0_to_100():
    for group in (LEGITIMATE_EMAILS, PHISHING_EMAILS, BEC_EMAILS, IMPERSONATION_EMAILS, FRAUD_EMAILS, MALWARE_EMAILS):
        for email in group:
            result = analyze_email(email)
            assert 0 <= result["risk_score"] <= 100


def test_scores_dict_has_exact_required_keys():
    result = analyze_email(BEC_EMAILS[0])
    assert set(result["scores"].keys()) == {
        "phishing", "bec", "impersonation", "credential_theft", "financial_fraud",
    }
    for v in result["scores"].values():
        assert 0.0 <= v <= 1.0


def test_features_dict_matches_feature_order():
    from backend.detection.attack_dna import FEATURE_ORDER
    result = analyze_email(BEC_EMAILS[0])
    assert set(result["features"].keys()) == set(FEATURE_ORDER)


def test_classification_is_always_a_known_label():
    from backend.detection.classifier import CLASSIFICATIONS
    for group in (LEGITIMATE_EMAILS, PHISHING_EMAILS, BEC_EMAILS, IMPERSONATION_EMAILS, FRAUD_EMAILS, MALWARE_EMAILS):
        for email in group:
            result = analyze_email(email)
            assert result["classification"] in CLASSIFICATIONS
