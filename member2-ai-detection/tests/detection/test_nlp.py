from backend.detection.nlp import analyze_text


def test_neutral_email_has_no_signals():
    result = analyze_text("Team lunch Friday", "Just confirming lunch at 12:30, let me know if you can't make it.")
    for dim in result.dimensions.values():
        assert dim.label in ("NONE", "LOW")


def test_urgency_detected():
    result = analyze_text("URGENT ACTION REQUIRED", "Please respond immediately, this is time-sensitive.")
    assert result.dimensions["urgency"].label in ("MEDIUM", "HIGH")
    assert result.dimensions["urgency"].matches


def test_financial_manipulation_detected():
    result = analyze_text("Payment request", "Please process a wire transfer to the new bank account today.")
    assert result.dimensions["financial_manipulation"].label in ("MEDIUM", "HIGH")


def test_credential_request_detected():
    result = analyze_text("Verify your account", "Please confirm your identity and re-enter your password to continue.")
    assert result.dimensions["credential_request"].label in ("MEDIUM", "HIGH")
    assert result.dimensions["account_verification"].label in ("MEDIUM", "HIGH")


def test_authority_and_confidentiality_pressure():
    body = "This comes directly from the CEO. Please keep this confidential and do not discuss it with anyone."
    result = analyze_text("Confidential request", body)
    assert result.dimensions["authority_pressure"].label in ("MEDIUM", "HIGH")
    assert result.dimensions["confidentiality_pressure"].label in ("MEDIUM", "HIGH")


def test_executive_impersonation_language_flag():
    body = "I'm currently in a meeting and can't talk right now. I need you to handle this quietly."
    result = analyze_text("Quick task", body)
    assert result.exec_impersonation_language is True
    assert result.exec_impersonation_matches


def test_suspicious_cta_detected():
    result = analyze_text("Document shared", "Click here to view the secure document before it expires.")
    assert result.dimensions["suspicious_cta"].label in ("MEDIUM", "HIGH")
