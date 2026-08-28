# Email Threat Forensics AI — Member 2 Deliverable (AI Detection Module)

This is the **detection module** (`backend/detection/`) for the AI-Powered
Email Threat Detection, Geolocation & Forensic Intelligence Platform
hackathon project — Member 2's piece of the pipeline:

```
Member 1 (forensics)  →  YOU (AI detection + risk + Attack DNA)  →  Member 3 (memory/correlation)  →  Member 4 (dashboard)
```

Full design rationale, scoring tables, and the exact output contract are in
[`docs/detection-module.md`](docs/detection-module.md) — read that first if
you're integrating with this module.

## Quickstart

```bash
pip install -r requirements.txt

# run the standalone detection API
uvicorn backend.main:app --reload --port 8000

# in another terminal
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @samples/bec/bec_01.json

# run the test suite
pytest tests/detection -q
```

## What's implemented

- [x] Technical/header risk scoring — explainable, additive, capped 0–100 (`backend/detection/scoring.py`)
- [x] NLP / social-engineering language analysis (`backend/detection/nlp.py`)
- [x] Threat classification: LEGITIMATE / SUSPICIOUS / PHISHING / BEC / IMPERSONATION / CREDENTIAL_THEFT / FINANCIAL_FRAUD / MALWARE
- [x] Executive impersonation detection (address + language based)
- [x] BEC-specific pattern detection (wire transfer, gift cards, bank-detail changes, urgency + confidentiality pressure)
- [x] Attack DNA fingerprint generator (meaningful, not random — see docs)
- [x] Attack DNA / feature-vector similarity against a seeded mock historical case store
- [x] `POST /analyze` FastAPI endpoint (`backend/main.py`)
- [x] 57 passing tests across scoring, NLP, Attack DNA, end-to-end classification, and the API (`tests/detection/`)
- [x] Synthetic sample emails covering all required categories (`samples/`)
- [x] Never claims confirmed attribution — all outputs use "indicates", "suggests", "potentially related" language

## Repo layout (this module's slice)

```
backend/
├── main.py                        FastAPI app + POST /analyze
└── detection/
    ├── classifier.py              orchestrator → final contract JSON
    ├── nlp.py                     social-engineering language analysis
    ├── scoring.py                 technical/header risk scoring
    ├── attack_dna.py              feature vector, DNA fingerprint, similarity
    └── data/historical_cases.json seeded mock threat memory (7 cases)

tests/detection/                   57 tests (pytest)
samples/                           synthetic test emails by category
docs/detection-module.md           full design doc + output contract
```

## Notes for the team

- Output JSON keeps every field name from the agreed contract
  (`classification`, `risk_score`, `risk_level`, `scores`, `indicators`,
  `social_engineering`, `attack_dna`, `features`, `dna_similarity`) — nothing
  renamed or removed. A handful of additional, clearly-labeled fields
  (`risk_breakdown`, `social_engineering_detail`, `impersonation_analysis`,
  `attack_dna_breakdown`, `summary`, `scores_extended`) were added to make
  the dashboard's "why" panel easier to build; see §5 of the docs for the
  full rationale, and flag if the team would rather keep the payload leaner.
- No ML training, no external API keys, no `.env` — everything runs offline
  and deterministically, by design, for a fast/reliable hackathon demo.
- Ready to swap in Member 1's real forensic JSON: same field names, no code
  changes required unless their schema differs (see docs §7).
