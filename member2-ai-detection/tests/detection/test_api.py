from fastapi.testclient import TestClient

from backend.main import app
from tests.detection.mock_data import BEC_EMAILS, LEGITIMATE_EMAILS

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_analyze_endpoint_legitimate_email():
    resp = client.post("/analyze", json=LEGITIMATE_EMAILS[0])
    assert resp.status_code == 200
    body = resp.json()
    assert body["classification"] == "LEGITIMATE"


def test_analyze_endpoint_bec_email_full_contract():
    resp = client.post("/analyze", json=BEC_EMAILS[0])
    assert resp.status_code == 200
    body = resp.json()
    for key in ("classification", "risk_score", "risk_level", "scores", "indicators",
                "social_engineering", "attack_dna", "features", "dna_similarity"):
        assert key in body


def test_analyze_endpoint_accepts_extra_fields_without_error():
    payload = dict(BEC_EMAILS[0])
    payload["some_future_forensic_field"] = {"nested": True}
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200


def test_analyze_with_remember_case_query_param():
    resp = client.post("/analyze?remember_case=true", json=BEC_EMAILS[1])
    assert resp.status_code == 200
