"""
headers.py
Header forensics: received-chain reconstruction, identity mismatch
checks, anomaly list generation.

NEVER call the earliest hop "the attacker's IP" - call it the
"earliest reliable observed source". Could be VPN/proxy/Tor/cloud/
compromised host/relay.
"""
import re

_IP_RE = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
_FROM_RE = re.compile(r"from\s+([^\s;]+)", re.I)
_BY_RE = re.compile(r"by\s+([^\s;]+)", re.I)
_TIME_RE = re.compile(r";\s*(.+)$")
_ADDR_DOMAIN_RE = re.compile(r"@([\w.-]+)")


def domain_of(address):
    m = _ADDR_DOMAIN_RE.search(address or "")
    return m.group(1).lower() if m else ""


def parse_received_chain(msg):
    """
    Preserves ACTUAL chronological order. get_all("Received") returns
    headers top-to-bottom as they appear in the file; the topmost is
    the MOST RECENTLY added (closest to recipient). Reversing that
    list gives chronological order: hop 1 = oldest = closest to the
    true origin. Do NOT randomly reverse - this reversal is the
    correct one, done exactly once.
    """
    received_headers = msg.get_all("Received", []) or []
    chain = []
    for idx, header in enumerate(reversed(received_headers)):
        h = str(header)
        ip_m = _IP_RE.search(h)
        from_m = _FROM_RE.search(h)
        by_m = _BY_RE.search(h)
        time_m = _TIME_RE.search(h)
        chain.append({
            "hop": idx + 1,
            "from_host": from_m.group(1) if from_m else None,
            "by_host": by_m.group(1) if by_m else None,
            "ip": ip_m.group(1) if ip_m else None,
            "timestamp": time_m.group(1).strip() if time_m else None,
            "raw": h.strip(),
        })
    return chain


def earliest_observed_source(chain):
    for hop in chain:
        if hop["ip"]:
            return hop
    return None


def detect_anomalies(email_fields, auth_results, received_chain):
    anomalies = []
    from_domain = domain_of(email_fields.get("from", ""))
    reply_to_domain = domain_of(email_fields.get("reply_to", ""))
    return_path_domain = domain_of(email_fields.get("return_path", ""))
    spf_domain = auth_results.get("spf_domain", "")
    dkim_domain = auth_results.get("dkim_domain", "")

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append({
            "type": "reply_to_mismatch",
            "severity": "HIGH",
            "description": "Reply-To domain differs from visible sender domain.",
            "evidence": {"from": from_domain, "reply_to": reply_to_domain},
        })

    if return_path_domain and from_domain and return_path_domain != from_domain:
        anomalies.append({
            "type": "return_path_mismatch",
            "severity": "MEDIUM",
            "description": "Return-Path domain differs from visible sender domain.",
            "evidence": {"from": from_domain, "return_path": return_path_domain},
        })

    if spf_domain and from_domain and spf_domain != from_domain:
        anomalies.append({
            "type": "spf_alignment_mismatch",
            "severity": "MEDIUM",
            "description": "SPF-authenticated domain does not align with visible From domain.",
            "evidence": {"from": from_domain, "spf_domain": spf_domain},
        })

    if dkim_domain and from_domain and dkim_domain != from_domain:
        anomalies.append({
            "type": "dkim_alignment_mismatch",
            "severity": "MEDIUM",
            "description": "DKIM-signing domain does not align with visible From domain.",
            "evidence": {"from": from_domain, "dkim_domain": dkim_domain},
        })

    if auth_results.get("spf") == "fail":
        anomalies.append({"type": "spf_failure", "severity": "HIGH",
                           "description": "SPF authentication failed."})
    if auth_results.get("dkim") == "fail":
        anomalies.append({"type": "dkim_failure", "severity": "HIGH",
                           "description": "DKIM authentication failed."})
    if auth_results.get("dmarc") == "fail":
        anomalies.append({"type": "dmarc_failure", "severity": "MEDIUM",
                           "description": "DMARC authentication failed."})

    if not received_chain:
        anomalies.append({"type": "no_received_chain", "severity": "LOW",
                           "description": "No Received headers found - relay path could not be reconstructed."})

    return anomalies
