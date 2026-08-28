"""
authentication.py
SPF / DKIM / DMARC extraction + alignment domains.
Evidence, not proof - never treat a failure alone as confirmed phishing.
"""
import re


def parse_authentication_results(msg):
    raw = msg.get("Authentication-Results", "")
    result = {"spf": "none", "dkim": "none", "dmarc": "none",
              "spf_domain": "", "dkim_domain": "", "raw": raw}

    if raw:
        for field in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{field}=(\w+)", raw, re.I)
            if m:
                result[field] = m.group(1).lower()

        spf_domain_m = re.search(r"smtp\.mailfrom=([\w.-]+)", raw, re.I)
        if spf_domain_m:
            result["spf_domain"] = spf_domain_m.group(1).lower()

        dkim_domain_m = re.search(r"header\.d=([\w.-]+)", raw, re.I)
        if dkim_domain_m:
            result["dkim_domain"] = dkim_domain_m.group(1).lower()

    return result
