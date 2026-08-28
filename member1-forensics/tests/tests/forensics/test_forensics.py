import os

import parser
import headers as headers_mod
import authentication
import indicators
import attachments as attachments_mod

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SAMPLES = os.path.join(ROOT, "samples")


def _pipeline(path):
    msg = parser.parse_eml(path)
    email_fields = parser.extract_basic_headers(msg)
    body = parser.extract_body(msg)
    raw_attachments = parser.extract_attachments(msg)
    auth_results = authentication.parse_authentication_results(msg)
    chain = headers_mod.parse_received_chain(msg)
    text = f"{body['plain']} {body['html']} {email_fields.get('from', '')}"
    ips = indicators.extract_ips(text)
    domains = indicators.extract_domains(text)
    urls = indicators.extract_urls(text)
    attachments_out = attachments_mod.analyze_attachments(raw_attachments)
    anomalies = headers_mod.detect_anomalies(email_fields, auth_results, chain)
    return {
        "email": email_fields, "body": body, "auth": auth_results,
        "chain": chain, "ips": ips, "domains": domains, "urls": urls,
        "attachments": attachments_out, "anomalies": anomalies,
    }


def test_basic_parsing():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert r["email"]["subject"]
    assert r["email"]["from"]


def test_reply_to_mismatch_detected():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    types = [a["type"] for a in r["anomalies"]]
    assert "reply_to_mismatch" in types


def test_return_path_extraction():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert r["email"]["return_path"]


def test_multiple_received_headers_correct_ordering():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert len(r["chain"]) >= 2
    # hop 1 must be the earliest/external hop, not the internal relay
    assert r["chain"][0]["ip"] == "203.0.113.45"


def test_spf_dkim_dmarc_extraction():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert r["auth"]["spf"] in ("pass", "fail", "none", "softfail")
    assert r["auth"]["dkim"] in ("pass", "fail", "none")
    assert r["auth"]["dmarc"] in ("pass", "fail", "none")


def test_ip_domain_url_extraction():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert any("fake-login.com" in d for d in r["domains"])
    assert any(u.startswith("http") for u in r["urls"])


def test_attachment_hash_generated():
    r = _pipeline(os.path.join(SAMPLES, "bec", "bec.eml"))
    assert len(r["attachments"]) >= 1
    assert r["attachments"][0]["sha256"]


def test_legitimate_email_has_no_high_severity_anomalies():
    r = _pipeline(os.path.join(SAMPLES, "legitimate", "legitimate.eml"))
    high = [a for a in r["anomalies"] if a["severity"] == "HIGH"]
    assert len(high) == 0


def test_spoofed_email_flags_auth_failure_without_header_mismatch():
    r = _pipeline(os.path.join(SAMPLES, "spoofed", "spoofed.eml"))
    types = [a["type"] for a in r["anomalies"]]
    assert "spf_failure" in types
    assert "reply_to_mismatch" not in types  # From/Reply-To match here - it's spoofed infra, not mismatched headers


def test_phishing_email_flags_suspicious_url():
    r = _pipeline(os.path.join(SAMPLES, "phishing", "phishing.eml"))
    assert len(r["urls"]) >= 1


def test_malformed_email_does_not_crash(tmp_path):
    bad_file = tmp_path / "broken.eml"
    bad_file.write_bytes(b"Not a real email header block\n\nJust some text.")
    r = _pipeline(str(bad_file))
    assert r["email"] is not None
    assert isinstance(r["anomalies"], list)


def test_empty_email_does_not_crash(tmp_path):
    empty_file = tmp_path / "empty.eml"
    empty_file.write_bytes(b"")
    r = _pipeline(str(empty_file))
    assert isinstance(r["anomalies"], list)
