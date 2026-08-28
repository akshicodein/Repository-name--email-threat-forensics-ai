from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class InvestigationRequest(BaseModel):
    """Input contract — fields sourced from M1 (forensics) + M2 (detection).

    DO NOT rename these fields without full team approval (see team rules doc).
    """

    email_id: Optional[str] = None
    case_id: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    attack_dna: Optional[str] = None
    classification: Optional[str] = None
    risk_score: Optional[float] = None


class IPIntelligence(BaseModel):
    ip: str
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    hosting_type: Optional[str] = None
    reputation: Optional[str] = None
    is_vpn_or_proxy: Optional[bool] = None
    is_tor: Optional[bool] = None
    note: str = "Observed source infrastructure only — not a confirmed attacker location."


class DomainIntelligence(BaseModel):
    domain: str
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    is_newly_registered: Optional[bool] = None
    reputation: Optional[str] = None
    flags: List[str] = Field(default_factory=list)


class RelatedCase(BaseModel):
    case_id: str
    shared_indicators: List[str] = Field(default_factory=list)
    similarity: Optional[float] = None
    relationship: str = "Possible related infrastructure"


class CampaignResult(BaseModel):
    possible_campaign: Optional[str] = None
    confidence: float = 0.0
    related_case_ids: List[str] = Field(default_factory=list)
    summary: str = ""


class InfrastructureEvolutionEvent(BaseModel):
    date: str
    domain: Optional[str] = None
    ip: Optional[str] = None
    case_id: Optional[str] = None
    note: Optional[str] = None


class InvestigationResponse(BaseModel):
    ip_intelligence: List[IPIntelligence] = Field(default_factory=list)
    domain_intelligence: List[DomainIntelligence] = Field(default_factory=list)
    related_cases: List[RelatedCase] = Field(default_factory=list)
    campaign: CampaignResult = Field(default_factory=CampaignResult)
    infrastructure_evolution: List[InfrastructureEvolutionEvent] = Field(default_factory=list)
    graph: Dict[str, Any] = Field(default_factory=dict)
