import re

from backend.detection import attack_dna as dna


def _vec(**overrides):
    base = {k: 0.0 for k in dna.FEATURE_ORDER}
    base.update(overrides)
    return base


def test_feature_vector_has_all_expected_keys():
    v = dna.build_feature_vector(
        technical_indicators={"dmarc": "fail", "dkim": "pass", "spf": "pass", "reply_to_mismatch": False},
        url_flags={},
        nlp_raw_scores={},
        executive_impersonation_score=0.0,
    )
    assert set(v.keys()) == set(dna.FEATURE_ORDER)


def test_dna_format_is_five_hex_byte_groups():
    v = _vec(dmarc_fail=1.0, urgency=0.8, financial_manipulation=0.9)
    fingerprint = dna.generate_attack_dna(v)
    assert re.match(r"^[0-9A-F]{2}(-[0-9A-F]{2}){4}$", fingerprint)


def test_dna_not_a_pure_random_hash_is_deterministic():
    v = _vec(dmarc_fail=1.0, urgency=0.8, financial_manipulation=0.9)
    assert dna.generate_attack_dna(v) == dna.generate_attack_dna(v)


def test_similar_vectors_produce_similar_dna_bytes():
    v1 = _vec(dmarc_fail=1.0, dkim_fail=1.0, urgency=0.9, financial_manipulation=0.9, executive_impersonation=0.9)
    v2 = _vec(dmarc_fail=1.0, dkim_fail=0.9, urgency=0.85, financial_manipulation=0.95, executive_impersonation=0.85)
    d1 = dna.generate_attack_dna(v1)
    d2 = dna.generate_attack_dna(v2)
    # Compare byte-by-byte; similar inputs should mostly match or be very close
    bytes1 = [int(b, 16) for b in d1.split("-")]
    bytes2 = [int(b, 16) for b in d2.split("-")]
    diffs = [abs(a - b) for a, b in zip(bytes1, bytes2)]
    assert all(diff <= 20 for diff in diffs)


def test_dissimilar_vectors_produce_different_dna():
    v1 = _vec(dmarc_fail=1.0, dkim_fail=1.0, financial_manipulation=1.0, executive_impersonation=1.0)
    v2 = _vec(credential_request=1.0, account_verification=1.0, suspicious_url_keywords=1.0)
    assert dna.generate_attack_dna(v1) != dna.generate_attack_dna(v2)


def test_cosine_similarity_identical_vectors_is_one():
    v = _vec(urgency=0.7, financial_manipulation=0.5)
    assert abs(dna.cosine_similarity(v, v) - 1.0) < 1e-9


def test_cosine_similarity_empty_vectors_is_zero():
    v1 = _vec()
    v2 = _vec()
    assert dna.cosine_similarity(v1, v2) == 0.0


def test_compare_with_history_returns_seeded_matches():
    # BEC-like vector should be similar to the seeded BEC historical cases
    v = _vec(
        dmarc_fail=1.0, dkim_fail=1.0, spf_fail=1.0, reply_to_mismatch=1.0,
        urgency=0.85, authority_pressure=0.85, confidentiality_pressure=0.75,
        financial_manipulation=0.9, executive_impersonation=0.85,
    )
    matches = dna.compare_with_history(v, top_n=3, min_similarity=0.5)
    assert len(matches) > 0
    assert all(0 <= m["similarity"] <= 100 for m in matches)
    assert all("note" in m and "confirm" not in m["note"].lower() for m in matches)


def test_dna_byte_breakdown_explainable():
    v = _vec(dmarc_fail=1.0, dkim_fail=1.0)
    breakdown = dna.dna_byte_breakdown(v)
    assert len(breakdown) == 5
    assert breakdown[0]["category"] == "HEADER_AUTH"
    assert "dmarc_fail" in breakdown[0]["contributing_features"]


def test_register_and_find_new_case(tmp_path, monkeypatch):
    # Use a filename that doesn't exist yet, guaranteeing a clean slate even
    # though the autouse `isolate_historical_store` fixture already seeded
    # tmp_path/historical_cases.json with the shipped demo cases.
    monkeypatch.setattr(dna, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dna, "HISTORY_FILE", str(tmp_path / "fresh_history.json"))

    v = _vec(dmarc_fail=1.0, urgency=0.9, financial_manipulation=0.9)
    dna.register_case("TEST-001", dna.generate_attack_dna(v), "BEC", v, "Test case")

    history = dna.load_history()
    assert len(history) == 1
    assert history[0].case_id == "TEST-001"

    matches = dna.compare_with_history(v, min_similarity=0.5)
    assert matches[0]["case_id"] == "TEST-001"
    assert matches[0]["similarity"] == 100.0
