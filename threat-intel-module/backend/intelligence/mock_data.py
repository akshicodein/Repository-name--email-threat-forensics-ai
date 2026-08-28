"""Mock input so this module can be built and tested before M1/M2 are wired up.

Per the spec ("Work Independently First"):
    Mock IP/Domain -> Threat Intelligence -> Database -> Correlation -> Graph
Swap this for the real M1/M2 output once integration starts (Phase 7).
"""

MOCK_INPUT = {
    "email_id": "EMAIL-MOCK-001",
    "case_id": "CASE-MOCK-001",
    "ip_addresses": ["1.2.3.4"],
    "domains": ["fake-example.com"],
    "urls": ["http://fake-example.com/login"],
    "attack_dna": "A7-F3-C9-21",
    "classification": "BEC",
    "risk_score": 91,
}
