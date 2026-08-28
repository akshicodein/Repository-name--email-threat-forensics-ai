"""Investigation graph: Email <-> Domain <-> IP <-> ASN <-> Case <-> Campaign.

Always returns a plain nodes/edges dict (for M4's dashboard). If NEO4J_URI
is set, also best-effort pushes the same graph into Neo4j — never fails the
request if Neo4j is unavailable.
"""

from typing import Any


def build_investigation_graph(
    email_id: str | None,
    domains: list[str],
    ips: list[dict],
    attack_dna: str | None,
    related_cases: list[dict],
    campaign: dict,
) -> dict[str, Any]:
    nodes = []
    edges = []

    if email_id:
        nodes.append({"id": f"email:{email_id}", "type": "Email", "label": email_id})

    for d in domains:
        nid = f"domain:{d}"
        nodes.append({"id": nid, "type": "Domain", "label": d})
        if email_id:
            edges.append({"from": f"email:{email_id}", "to": nid, "type": "contains"})

    for ip in ips:
        ip_val = ip.get("ip") if isinstance(ip, dict) else ip
        nid = f"ip:{ip_val}"
        nodes.append({"id": nid, "type": "IP", "label": ip_val})
        for d in domains:
            edges.append({"from": f"domain:{d}", "to": nid, "type": "resolves_to"})
        asn = ip.get("asn") if isinstance(ip, dict) else None
        if asn:
            asn_id = f"asn:{asn}"
            nodes.append({"id": asn_id, "type": "ASN", "label": asn})
            edges.append({"from": nid, "to": asn_id, "type": "belongs_to"})

    if attack_dna and email_id:
        dna_id = f"dna:{attack_dna}"
        nodes.append({"id": dna_id, "type": "AttackDNA", "label": attack_dna})
        edges.append({"from": f"email:{email_id}", "to": dna_id, "type": "has"})

    for rc in related_cases:
        cid = rc.get("case_id") if isinstance(rc, dict) else rc
        case_node = f"case:{cid}"
        nodes.append({"id": case_node, "type": "Case", "label": cid})
        if email_id:
            edges.append({"from": f"email:{email_id}", "to": case_node, "type": "related_to"})

    campaign_name = campaign.get("possible_campaign") if isinstance(campaign, dict) else None
    if campaign_name:
        camp_id = f"campaign:{campaign_name}"
        nodes.append({"id": camp_id, "type": "Campaign", "label": campaign_name})
        for d in domains:
            edges.append({"from": f"domain:{d}", "to": camp_id, "type": "associated_with"})

    _try_push_neo4j(nodes, edges)

    return {"nodes": nodes, "edges": edges}


def _try_push_neo4j(nodes: list[dict], edges: list[dict]) -> None:
    from backend.intelligence.config import settings

    if not settings.NEO4J_URI:
        return  # optional — dict graph above is already returned regardless
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))
        with driver.session() as session:
            for n in nodes:
                session.run(
                    f"MERGE (x:{n['type']} {{id: $id}}) SET x.label = $label",
                    id=n["id"],
                    label=n["label"],
                )
            for e in edges:
                session.run(
                    "MATCH (a {id: $from_id}), (b {id: $to_id}) "
                    f"MERGE (a)-[:{e['type'].upper()}]->(b)",
                    from_id=e["from"],
                    to_id=e["to"],
                )
        driver.close()
    except Exception:
        # Neo4j is optional for the hackathon build — never fail the request
        pass
