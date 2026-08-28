import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from backend.intelligence.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200


def test_mock_investigation_returns_contract_shape():
    resp = client.post("/investigate/mock")
    assert resp.status_code == 200
    data = resp.json()
    for key in [
        "ip_intelligence",
        "domain_intelligence",
        "related_cases",
        "campaign",
        "infrastructure_evolution",
        "graph",
    ]:
        assert key in data


def test_second_investigation_finds_related_case():
    client.post(
        "/investigate",
        json={
            "case_id": "CASE-TEST-001",
            "ip_addresses": ["1.2.3.4"],
            "domains": ["evil-example.com"],
            "attack_dna": "A7-F3-C9-21",
        },
    )
    resp = client.post(
        "/investigate",
        json={
            "case_id": "CASE-TEST-002",
            "ip_addresses": ["1.2.3.4"],
            "domains": ["other-example.com"],
            "attack_dna": "A7-F3-C9-28",
        },
    )
    data = resp.json()
    related_ids = [c["case_id"] for c in data["related_cases"]]
    assert "CASE-TEST-001" in related_ids
