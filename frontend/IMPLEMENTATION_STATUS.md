# Frontend Implementation Status (Member 4)

**Last Updated:** Phase 3 Forensic Intelligence & Correlation Layer Complete

---

## 1. Completed in Phase 3

### 1. Interactive Campaign Correlation Graph (`CampaignGraphCanvas.jsx` & `CustomEntityNode.jsx`)
- **Library**: `@xyflow/react` (React Flow).
- **Node Types**: `Email`, `Domain`, `IP`, `URL`, `ASN`, `Case`, `Campaign`, `AttackDNA`.
- **Edge Types & Semantics**:
  - `CONTAINS` / `HAS` → `OBSERVED` (Cyan direct header facts).
  - `RESOLVES_TO` / `BELONGS_TO` → `CONFIRMED` (Emerald DNS & public BGP/ASN registry records).
  - `RELATED_TO` / `SIMILAR_TO` → `PROBABLE` (Violet cosine similarity matches from Threat Memory).
  - `ASSOCIATED_WITH` / `CORRELATES_WITH` → `INFERRED` (Orange tactical campaign clustering).
- **Capabilities**: Interactive node selection with slide-out entity telemetry drawer, entity filtering buttons (`ALL`, `Email`, `Domain`, `IP`, `AttackDNA`, `Case`, `Campaign`), search input, background grid, interactive mini-map, controls, and graceful fallback when correlation data is empty.

### 2. Infrastructure Evolution Timeline (`InfrastructureTimeline.jsx`)
- Chronological timeline tracking historical domain registrations and IP rotations across campaign clusters.
- Clickable event cards and modal inspector showing date, domain, IP, ASN, country, ISP, and rotation notes.
- Strict forensic framing: `INFRASTRUCTURE ROTATION OBSERVED` (avoiding premature claims of physical movement).

### 3. Dynamic Probable Attack Path Reconstruction (`ProbableAttackPath.jsx`)
- Dynamic attack sequence reconstruction derived purely from active evidence (`Inbound Delivery` → `Authentication Evasion` → `Social Engineering` → `Credential Harvesting / Payload Delivery` → `Impact / Wire Demand`).
- Strict certainty labels:
  - `SUPPORTED`: Direct cryptographic/header facts.
  - `PROBABLE`: High multi-indicator correlation.
  - `INFERRED`: Tactical objective deduction.
- Expandable stage cards detailing supporting evidence items and confidence percentages.

### 4. Evidence Provenance Chain (`EvidenceProvenanceChain.jsx`)
- "WHY DID THE SYSTEM FLAG THIS EMAIL?" chronological forensic reasoning timeline.
- Explicit Provenance Source Labels:
  - `MEMBER 1 — FORENSICS ENGINE`
  - `MEMBER 2 — AI DETECTION`
  - `MEMBER 3 — THREAT INTELLIGENCE`
  - `THREAT MEMORY`
  - `CORRELATION ENGINE`
- Demonstrates how each engine contributed to the verdict with certainty tags (`CONFIRMED`, `OBSERVED`, `PROBABLE`, `INFERRED`).

### 5. Investigation Case Summary & Analyst Actions (`InvestigationCaseSummary.jsx`)
- Executive summary card presenting Case ID, threat level, risk score, Attack DNA, and deterministic narrative conclusion.
- Analyst session controls:
  - "Mark as Investigated" in-session status toggle.
  - "Export Forensic Report" action.
  - "Copy Case ID", "Copy All IOCs", "Copy Attack DNA" quick buttons.

### 6. Print-Ready Forensic Report View (`ForensicReportView.jsx`)
- Printable forensic dossier view (`04. FORENSIC REPORT` and `Ctrl + P`).
- Print-optimized CSS (`@media print`) hiding navigation, buttons, and interactive chrome, while structuring Case Information, Email Forensics, Cryptographic Authentication, Verified Evidence, IOCs, Infrastructure Telemetry, Attack DNA, and Investigation Attestation into clean tabular printouts.

---

## 2. Backend Data & Graph Contracts Used

| Component | Backend Source | Real / Mock Data Contract |
|---|---|---|
| **Campaign Graph** | Member 3 `POST /investigate` (`graph.nodes`, `graph.edges`) | Live microservice or normalized mock threat memory |
| **Infrastructure Timeline** | Member 3 `POST /investigate` (`infrastructure_evolution`) | Chronological rotation events |
| **Threat Memory** | Member 2 `POST /analyze` (`dna_similarity`) + Member 3 (`related_cases`) | Cosine similarity & shared IOC clusters |
| **Attack Path** | Derived from Member 1 (`forensics`), Member 2 (`detection`), Member 3 (`intelligence`) | Dynamic heuristic rules based on active evidence |
| **Evidence Provenance** | Member 1 (`anomalies`), Member 2 (`risk_breakdown`, `social_engineering_detail`), Member 3 (`campaign`) | Provenance-tagged chronological reasoning |

---

## 3. Remaining Work / Phase 4 Recommendation

The next phase should focus exclusively on:
- End-to-end backend integration testing against live microservice endpoints.
- Error boundary hardening and offline network reconnects.
- Performance optimization and production release polish.
