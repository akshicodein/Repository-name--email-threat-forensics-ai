# Member 3 — Threat Intelligence + Threat Memory + Campaign Correlation

This is the investigation/correlation layer of the phishing-forensics pipeline.
It owns `backend/intelligence/` + `database/` per the team's folder ownership rules
and must not touch `backend/forensics/` (M1), `backend/detection/` (M2), or
`frontend/` (M4).

## Core flow

```
IP + Domain + Attack DNA
        │
        ▼
Threat Intelligence   (IP geo/ASN/reputation, domain DNS/RDAP)
        │
        ▼
Threat Memory         (SQLite/Postgres store of past cases)
        │
        ▼
Campaign Correlation  (shared indicators + Attack DNA similarity)
        │
        ▼
Infrastructure Evolution (domain/IP rotation over time)
        │
        ▼
Investigation Graph   (nodes/edges, optional Neo4j push)
        │
        ▼
M4 Dashboard
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # fill in API keys if you have them — all optional
uvicorn backend.intelligence.main:app --reload --port 8003
```

The API keys (IPinfo, AbuseIPDB, VirusTotal, Neo4j) are **all optional**. Without them
the module still runs end-to-end — IP/domain enrichment just returns less detail, and
the graph stays as a plain dict instead of also being pushed to Neo4j.

## Endpoints

- `GET /health` — liveness check
- `POST /investigate` — real pipeline. Body matches `InvestigationRequest` in
  `backend/intelligence/models.py` (fields sourced from M1 forensics + M2 detection:
  `ip_addresses`, `domains`, `urls`, `attack_dna`, `classification`, `risk_score`, plus
  `email_id`/`case_id`).
- `POST /investigate/mock` — runs the same pipeline against the spec's mock payload
  (`backend/intelligence/mock_data.py`) so you can build/demo before M1 and M2 are wired up.

### Output contract (goes straight to M4)

```json
{
  "ip_intelligence": [],
  "domain_intelligence": [],
  "related_cases": [{"case_id": "CASE-017", "similarity": 0.93}],
  "campaign": {"possible_campaign": "CAMPAIGN-04", "confidence": 0.88},
  "infrastructure_evolution": [],
  "graph": {"nodes": [], "edges": []}
}
```

Do not rename these top-level fields without team agreement — this is the shared
API contract from the team rules doc.

## Language, always

- IP/geo results are **"Observed source infrastructure associated with X"**, never
  "the attacker's exact location".
- DNA similarity / shared-indicator results are **"possible campaign relationship"**,
  never "confirmed same attacker".

These phrasings are baked into the model defaults and summaries — keep it that way
when you extend the module.

## Running tests

```bash
pytest
```

## Development order (matches the spec's phases)

1. IP intelligence (`ip_intel.py`)
2. Domain intelligence (`domain_intel.py`)
3. Threat Memory (`db.py`)
4. Correlation (`correlation.py`)
5. Infrastructure evolution (`evolution.py`)
6. Investigation graph (`graph.py`)
7. Integration with M1 (forensics) + M2 (detection) via `main.py`'s `/investigate`

## Folder layout

```
backend/
  intelligence/
    config.py        # env-driven settings, all API keys optional
    models.py         # API contract (Pydantic)
    mock_data.py       # spec's mock payload for independent development
    ip_intel.py         # IPinfo + AbuseIPDB enrichment
    domain_intel.py      # DNS + RDAP enrichment
    db.py                 # Threat Memory (SQLite)
    correlation.py          # shared indicators + Attack DNA similarity + campaign scoring
    evolution.py              # infrastructure rotation detection
    graph.py                    # nodes/edges graph, optional Neo4j push
    main.py                      # FastAPI app / /investigate endpoint
database/
  schema.sql            # PostgreSQL schema for production migration
tests/
  test_pipeline.py       # end-to-end tests against /investigate and /investigate/mock
```

## Golden rule

Change anything **inside** this module freely. Don't change the **input contract**
(fields in `InvestigationRequest`) or **output contract** (fields in
`InvestigationResponse`) without telling the team first.
