"""IP enrichment: geolocation, ASN/ISP, reputation.

Reminder (team rules): never label this "the attacker's exact location".
Always frame it as observed source infrastructure.
"""

import httpx
from backend.intelligence.config import settings
from backend.intelligence.models import IPIntelligence

PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "172.16.")


def _is_private(ip: str) -> bool:
    return ip.startswith(PRIVATE_PREFIXES)


def _lookup_ipinfo(ip: str) -> dict:
    if not settings.IPINFO_TOKEN:
        return {}
    try:
        resp = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": settings.IPINFO_TOKEN},
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def _lookup_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {}
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception:
        return {}


def _reputation_from_score(score) -> str:
    if score is None:
        return "unknown"
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def enrich_ip(ip: str) -> IPIntelligence:
    if _is_private(ip):
        return IPIntelligence(
            ip=ip,
            reputation="not_applicable",
            note="Private/internal address — no external enrichment applicable.",
        )

    geo = _lookup_ipinfo(ip)
    abuse = _lookup_abuseipdb(ip)

    org = geo.get("org", "")  # ipinfo format: "AS12345 Example Hosting"
    asn = org.split(" ")[0] if org.startswith("AS") else None
    isp = " ".join(org.split(" ")[1:]) if org.startswith("AS") else (org or None)

    abuse_score = abuse.get("abuseConfidenceScore")
    reputation = _reputation_from_score(abuse_score) if abuse else "unknown"

    privacy = geo.get("privacy") if isinstance(geo.get("privacy"), dict) else {}

    return IPIntelligence(
        ip=ip,
        country=geo.get("country"),
        region=geo.get("region"),
        city=geo.get("city"),
        isp=isp,
        asn=asn,
        org=org or None,
        hosting_type="cloud_or_vps" if org and ("hosting" in org.lower() or "cloud" in org.lower()) else None,
        reputation=reputation,
        is_vpn_or_proxy=bool(privacy.get("vpn")) if privacy else None,
        is_tor=bool(privacy.get("tor")) if privacy else None,
    )


def enrich_ips(ips: list[str]) -> list[IPIntelligence]:
    return [enrich_ip(ip) for ip in dict.fromkeys(ips)]  # de-dupe, keep order
