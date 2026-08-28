"""Member 3 — Threat Intelligence + Threat Memory + Campaign Correlation.

Core flow (per spec):
    IP + Domain + Attack DNA
        -> Threat Intelligence
        -> Threat Memory
        -> Campaign Correlation
        -> Infrastructure Evolution
        -> Investigation Graph
        -> M4 Dashboard
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.intelligence import db
from backend.intelligence.models import InvestigationRequest, InvestigationResponse
from backend.intelligence.mock_data import MOCK_INPUT
from backend.intelligence.ip_intel import enrich_ips
from backend.intelligence.domain_intel import enrich_domains
from backend.intelligence.correlation import find_related_cases, correlate_campaign
from backend.intelligence.evolution import track_infrastructure_evolution
from backend.intelligence.graph import build_investigation_graph

app = FastAPI(title="Member 3 — Threat Intelligence + Threat Memory + Campaign Correlation")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before integrating with M4 in prod
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    db.init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/investigate", response_model=InvestigationResponse)
def investigate(req: InvestigationRequest):
    case_id = req.case_id or "CASE-UNASSIGNED"

    ip_intel = enrich_ips(req.ip_addresses)
    domain_intel = enrich_domains(req.domains)

    related_cases = find_related_cases(case_id, req.ip_addresses, req.domains, req.attack_dna)
    campaign = correlate_campaign(related_cases)
    evolution = track_infrastructure_evolution(req.ip_addresses)

    graph = build_investigation_graph(
        email_id=req.email_id,
        domains=req.domains,
        ips=[i.model_dump() for i in ip_intel],
        attack_dna=req.attack_dna,
        related_cases=[rc.model_dump() for rc in related_cases],
        campaign=campaign.model_dump(),
    )

    # Persist into Threat Memory so future investigations can correlate against this one
    db.save_case(
        case_id=case_id,
        email_id=req.email_id,
        attack_dna=req.attack_dna,
        classification=req.classification,
        risk_score=req.risk_score,
        ips=req.ip_addresses,
        domains=req.domains,
    )

    return InvestigationResponse(
        ip_intelligence=ip_intel,
        domain_intelligence=domain_intel,
        related_cases=related_cases,
        campaign=campaign,
        infrastructure_evolution=evolution,
        graph=graph,
    )


@app.post("/investigate/mock", response_model=InvestigationResponse)
def investigate_mock():
    """Runs the pipeline against the spec's mock payload — use before M1/M2 are wired up."""
    return investigate(InvestigationRequest(**MOCK_INPUT))
