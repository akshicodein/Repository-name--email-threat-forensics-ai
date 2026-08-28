# Email Threat Forensics AI — Frontend (Member 4)

AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform.

This frontend serves as the centralized Security Operations Center (SOC) dashboard for visualizing deep email header forensics, AI-driven threat detection, Attack DNA fingerprints, and threat intelligence correlation graphs.

---

## 🚀 Quickstart

### Prerequisites
- Node.js (v18+)
- npm (v9+)

### Installation & Startup

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend runs at `http://localhost:3000`.

---

## 🧭 Platform Views & Modules

### 1. Ingest & Upload (`01. INGEST`)
- Drag-and-drop RFC 822 `.eml` upload, format validation, size limit enforcement.
- Pre-configured sample incident launcher (BEC Wire Fraud, Credential Phishing, Legitimate Business Review).
- 10-stage animated investigation progress pipeline.

### 2. Threat Dashboard (`02. DASHBOARD`)
- 240° SVG arc radial risk score meter (0–100) and multi-category confidence distribution.
- "Why is this Suspicious?" explainable evidence dossier.
- RFC 822 forensic metadata and domain mismatch alerts.
- Cryptographic Authentication Matrix (SPF, DKIM, DMARC) and header anomalies.
- Extracted IOC Vault (IPs, domains, URLs with threat keyword flags, attachments).
- Chronological Observed Relay Path with forensic attribution caveats.
- IP network intelligence and domain WHOIS records.
- Geographic network infrastructure location telemetry.
- 5-byte Attack DNA behavioral fingerprint and 19-dimension feature matrix.
- Historical Threat Memory similarity matches.

### 3. Forensic Intelligence & Graph (`03. GRAPH & TIMELINE`)
- **Interactive Campaign Correlation Graph (`@xyflow/react`)**: Multi-hop entity graph (`Email`, `Domain`, `IP`, `URL`, `ASN`, `Case`, `Campaign`, `AttackDNA`) with pan, zoom, entity search/filter, and slide-out node inspector.
- **Infrastructure Evolution Timeline**: Chronological rotation tracking of domain registrations and hosting server migrations.
- **Dynamic Probable Attack Path**: Evidence-derived attack stage progression (`SUPPORTED`, `PROBABLE`, `INFERRED`) with expandable supporting facts.
- **Evidence Provenance Chain**: Chronological reasoning pipeline with explicit `MEMBER 1`, `MEMBER 2`, and `MEMBER 3` source tags.
- **Investigation Case Summary & Analyst Actions**: Case dossier summary with in-session "Mark as Investigated" toggle, IOC export tools, and report triggers.

### 4. Forensic Report Export (`04. FORENSIC REPORT`)
- Dedicated print-friendly report view styled with `@media print` for single/multi-page printout and PDF export via `Ctrl + P` (or Print button).
- Structured tabular report covering Case Information, Email Forensics, Authentication, Indicators, Relay Path, Attack DNA, and Forensic Attestation.

---

## 🛠️ Microservice Architecture & API Contracts

- **Member 1 Forensics Engine (`member1-forensics/` - Port 8001)**: `POST /parse-email`
- **Member 2 AI Threat Detection (`member2-ai-detection/` - Port 8000)**: `POST /analyze`
- **Member 3 Threat Intelligence & Memory (`threat-intel-module/` - Port 8002)**: `POST /investigate`
