"""
tests/detection/conftest.py

Ensures the test suite never mutates the shipped demo seed data at
backend/detection/data/historical_cases.json. Any test that registers a new
case (directly or via POST /analyze?remember_case=true) is redirected to a
throwaway temp copy instead - seeded with the same demo cases so similarity
tests still have real historical data to match against.
"""

import shutil

import pytest

from backend.detection import attack_dna as dna


@pytest.fixture(autouse=True)
def isolate_historical_store(tmp_path, monkeypatch):
    original_history_file = dna.HISTORY_FILE
    tmp_history_file = tmp_path / "historical_cases.json"
    shutil.copyfile(original_history_file, tmp_history_file)

    monkeypatch.setattr(dna, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dna, "HISTORY_FILE", str(tmp_history_file))
    yield
