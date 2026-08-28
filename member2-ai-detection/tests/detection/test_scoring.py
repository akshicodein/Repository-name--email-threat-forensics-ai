from backend.detection import scoring


def test_clean_email_scores_zero():
    forensic = {
        "sender": "sarah@company.com", "reply_to": "sarah@company.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "domains": ["company.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    assert result.score == 0
    assert result.breakdown == []


def test_dmarc_dkim_spf_fail_adds_points():
    forensic = {
        "sender": "x@evil.com", "reply_to": "x@evil.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["evil.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert {"DMARC_FAIL", "DKIM_FAIL", "SPF_FAIL"}.issubset(fired)
    assert result.score >= scoring.WEIGHTS["DMARC_FAIL"] + scoring.WEIGHTS["DKIM_FAIL"] + scoring.WEIGHTS["SPF_FAIL"]


def test_reply_to_mismatch_detected():
    forensic = {
        "sender": "ceo@fake-company.com", "reply_to": "random@gmail.com",
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "urls": [], "domains": ["fake-company.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "REPLY_TO_MISMATCH" in fired


def test_lookalike_domain_detected_against_expected_domain():
    forensic = {
        "sender": "it@compnay.com", "reply_to": "it@compnay.com",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["compnay.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "LOOKALIKE_DOMAIN" in fired


def test_lookalike_domain_detected_against_brand_hint():
    forensic = {
        "sender": "support@paypa1-secure.com", "reply_to": "support@paypa1-secure.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["paypa1-secure.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "LOOKALIKE_DOMAIN" in fired


def test_suspicious_url_keyword_and_ip_literal():
    forensic = {
        "sender": "x@evil.top", "reply_to": "x@evil.top",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://198.51.100.5/verify-login"],
        "domains": ["evil.top"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "IP_LITERAL_URL" in fired
    assert "SUSPICIOUS_URL_KEYWORDS" in fired
    assert "SUSPICIOUS_TLD" in fired


def test_shortened_url_detected():
    forensic = {
        "sender": "x@evil.com", "reply_to": "x@evil.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["https://bit.ly/abc123"], "domains": ["evil.com"],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "SHORTENED_URL" in fired


def test_attachment_risk_flagged():
    forensic = {
        "sender": "x@evil.com", "reply_to": "x@evil.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": [], "domains": ["evil.com"],
        "attachments": [{"name": "invoice.exe"}],
    }
    result = scoring.score_technical_indicators(forensic)
    fired = {r.indicator for r in result.breakdown}
    assert "ATTACHMENT_RISK" in fired


def test_score_never_exceeds_100():
    forensic = {
        "sender": "ceo@paypa1-secure.xyz", "reply_to": "random@gmail.com",
        "expected_domain": "company.com",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://198.51.100.5/verify-login-secure", "https://bit.ly/x"],
        "domains": ["paypa1-secure.xyz"],
        "attachments": [{"name": "payload.exe"}],
    }
    result = scoring.score_technical_indicators(forensic)
    assert 0 <= result.score <= 100


def test_risk_level_thresholds():
    assert scoring.risk_level_from_score(10) == "LOW"
    assert scoring.risk_level_from_score(35) == "MEDIUM"
    assert scoring.risk_level_from_score(60) == "HIGH"
    assert scoring.risk_level_from_score(90) == "CRITICAL"
