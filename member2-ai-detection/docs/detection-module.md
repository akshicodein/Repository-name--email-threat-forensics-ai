# Detection Module (Member 2) — `backend/detection/`

AI Threat Detection · Risk Scoring · NLP/Social-Engineering Analysis · Attack DNA

This document explains how the module works, how to run/test it, and exactly
what Member 3 and Member 4 can expect from its output.

## 1. What it does

Given forensic evidence + email content (mock JSON now, Member 1's real
Forensic JSON later — same field names), this module answers:

1. Is it suspicious, and what type of threat is it?
2. How dangerous is it (0–100, explainable)?
3. Why is it suspicious (technical + language indicators)?
4. What's its Attack DNA (a compact fingerprint for campaign correlation)?
5. Have we seen something like this before?

It is a **hybrid, rules-first system** — no training data required, every
point on the risk score and every classification decision is traceable to a
named indicator. This was a deliberate choice for the hackathon: it's fast to
build, trivial to demo, and easy to explain to judges. An LLM call for
human-readable explanation could be bolted on later (see §6) without changing
any of the underlying detection logic.

## 2. File map

| File | Responsibility |
|---|---|
| `scoring.py` | Technical/header risk scoring (SPF/DKIM/DMARC, Reply-To mismatch, lookalike domains, suspicious URLs, risky attachments). Additive, explainable, capped at 100. |
| `nlp.py` | Social-engineering language analysis (urgency, fear, authority pressure, financial/credential requests, confidentiality pressure, deadlines, CTAs, exec-impersonation phrasing). Keyword/regex based — no ML training needed. |
| `attack_dna.py` | Builds the 19-dimension normalized feature vector, derives the 5-byte Attack DNA fingerprint from it, and compares the vector against a small historical case store (mock "threat memory") using cosine similarity. |
| `classifier.py` | Orchestrator. Combines the above into the final classification, per-category probability scores, combined risk score, and the full contract-compliant JSON output. |
| `data/historical_cases.json` | Seeded mock "threat memory" (7 synthetic prior cases spanning BEC/PHISHING/IMPERSONATION/CREDENTIAL_THEFT/FINANCIAL_FRAUD/MALWARE) so Attack DNA similarity has something to match against out of the box. Real persistence belongs to Member 3's Threat Memory module long-term. |

`backend/main.py` exposes `POST /analyze` (FastAPI) as the standalone dev
entry point; `detection_router` can be mounted into the team's shared app
instead if one exists.

## 3. How the risk score works

Two additive point systems feed into one capped 0–100 score:

**Technical (`scoring.py`, see `WEIGHTS` dict):**

| Indicator | Points |
|---|---|
| DMARC failure | +25 |
| Reply-To mismatch | +20 |
| Lookalike/suspicious domain | +18 |
| DKIM failure | +12 |
| SPF failure | +12 |
| IP-literal URL | +12 |
| Suspicious URL keywords (login/verify/secure/...) | +10 |
| Freemail address for exec-styled sender | +8 |
| URL host doesn't match sender domain | +8 |
| Suspicious TLD (.top/.xyz/.click/...) | +8 |
| Risky attachment extension | +10 |
| Shortened URL | +6 |

**Language (`classifier.py`, `NLP_POINT_WEIGHTS`):** each social-engineering
dimension (urgency, financial manipulation, credential request, fear/threat,
authority pressure, confidentiality pressure, artificial deadline, suspicious
CTA, account verification) contributes points scaled by its
LOW/MEDIUM/HIGH label. Executive impersonation, when suspected, adds a flat
+10.

`risk_score = min(100, technical_points + language_points)`, then mapped to
LOW (<30) / MEDIUM (30–54) / HIGH (55–79) / CRITICAL (80+).

Every point is listed in the `risk_breakdown` field of the output (see §5) so
Member 4 can render a "why" panel exactly like the spec's example.

## 4. Attack DNA — how it stays meaningful (not random)

1. `attack_dna.build_feature_vector(...)` assembles a 19-dimension vector in
   `[0, 1]`, grouped into 5 semantic categories: header/auth behaviour,
   domain/URL characteristics, urgency/pressure language, broader social
   engineering, and financial/credential/impersonation intent.
2. `attack_dna.generate_attack_dna(vector)` turns each category's *average*
   into one hex byte (`00`–`FF`), joined as `XX-XX-XX-XX-XX`
   (e.g. `A7-F3-C9-21-88`). Because each byte is a quantized average of named
   features (not a cryptographic hash), **similar emails naturally produce
   similar or identical bytes** — you can literally point at the DNA string
   and explain what each pair of digits means (`attack_dna_breakdown` field
   does this programmatically).
3. **Similarity** is computed separately and more precisely, via cosine
   similarity over the full 19-dim feature vector (`compare_with_history`),
   not by comparing the DNA string. The DNA string is the human-readable
   label; the feature vector is the thing that's actually compared.
4. Similarity results are always phrased as "potentially related activity" /
   "possible campaign relationship" — **never** as confirmed common
   authorship, per the team's forensic-accuracy rules.

## 5. Output contract

`analyze_email(payload)` (and `POST /analyze`) returns:

```jsonc
{
  // --- required contract fields (DO NOT rename) ---
  "classification": "BEC",
  "risk_score": 91,
  "risk_level": "HIGH",
  "scores": {
    "phishing": 0.55, "bec": 0.87, "impersonation": 0.74,
    "credential_theft": 0.2, "financial_fraud": 0.54
  },
  "indicators": ["DMARC failure", "Reply-To mismatch", "Executive impersonation", "..."],
  "social_engineering": {
    "urgency": "HIGH", "authority_pressure": "HIGH",
    "financial_manipulation": "HIGH", "credential_request": "MEDIUM"
  },
  "attack_dna": "A7-F3-C9-21-88",
  "features": { "...": "19-dim normalized feature vector" },
  "dna_similarity": [
    { "case_id": "CASE-017", "attack_dna": "...", "similarity": 93.0,
      "note": "High similarity with previous case - potentially related activity.", "...": "..." }
  ],

  // --- additive extras (safe to ignore, never required) ---
  "scores_extended": { "...": "same as scores, plus malware" },
  "risk_breakdown": [ { "indicator": "DMARC_FAIL", "points": 25, "detail": "..." } ],
  "social_engineering_detail": { "...": "raw scores + matched phrases per dimension" },
  "impersonation_analysis": { "display_name": "...", "actual_sender_domain": "...", "expected_domain": "...", "..." },
  "attack_dna_breakdown": [ { "byte": "A7", "category": "HEADER_AUTH", "...": "..." } ],
  "summary": "AI assessment indicates HIGH risk (91/100). Classified as BEC based on: ..."
}
```

> **Note on scope:** the `scores_extended`, `risk_breakdown`,
> `social_engineering_detail`, `impersonation_analysis`,
> `attack_dna_breakdown`, and `summary` fields are **additions**, not
> renames — every field named in the original spec's OUTPUT CONTRACT is
> present with its original name and meaning. These extras exist purely to
> make the HOW/WHY easier to render on Member 4's dashboard and are safe to
> ignore. Flagging this per the "explain before changing the schema" rule —
> happy to remove any of them if the team prefers a leaner payload.

## 6. Running it

```bash
# from repo root
pip install fastapi "uvicorn[standard]" pytest httpx pydantic

# run the detection API standalone
uvicorn backend.main:app --reload --port 8000
# POST http://localhost:8000/analyze  with a forensic JSON body (see samples/)

# run the tests
pytest tests/detection -q
```

## 7. Extending later

- **Swap in Member 1's real forensic JSON:** no code changes needed as long
  as field names match (`subject`, `body`, `sender`, `reply_to`, `spf`,
  `dkim`, `dmarc`, `urls`, `domains`, optional `display_name`,
  `expected_domain`, `attachments`). If Member 1's schema differs, add a thin
  adapter function rather than changing `classifier.py`'s internals.
- **LLM explanation layer (optional):** call an LLM with `risk_breakdown` +
  `social_engineering_detail` + `indicators` as context and ask only for a
  1-paragraph human explanation. Never let the LLM decide the classification
  or score — those must stay in the deterministic, explainable path.
- **Member 3 (Threat Memory / Campaign Correlation):** consumes
  `attack_dna`, `features`, `classification`, and `dna_similarity` directly.
  `attack_dna.register_case(...)` shows the minimal shape Member 3's
  persistent store needs to replicate (`case_id`, `attack_dna`,
  `classification`, `features`, `summary`).
- **Member 4 (Dashboard):** every field in §5 is dashboard-ready JSON;
  `risk_breakdown` and `social_engineering_detail` are pre-shaped for a
  "why this score" panel, `attack_dna_breakdown` for an Attack-DNA explainer
  widget.
