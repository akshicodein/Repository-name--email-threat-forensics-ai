"""
report.py
Assembles the STABLE forensic JSON contract consumed by Member 2, 3, 4.
DO NOT rename top-level fields without team approval.
"""


def build_report(email_fields, raw_relevant_headers, received_chain,
                  auth_results, ips, domains, url_analysis, attachments,
                  anomalies):

    earliest = None
    for hop in received_chain:
        if hop["ip"]:
            earliest = hop
            break

    count = len(anomalies)
    risk_level = "HIGH" if count >= 3 else "MEDIUM" if count >= 1 else "LOW"

    return {
        "email": email_fields,
        "headers": {
            "received_chain": received_chain,
            "authentication_results": {
                "spf": auth_results.get("spf"),
                "dkim": auth_results.get("dkim"),
                "dmarc": auth_results.get("dmarc"),
                "spf_domain": auth_results.get("spf_domain"),
                "dkim_domain": auth_results.get("dkim_domain"),
                "raw": auth_results.get("raw"),
            },
            "raw_relevant_headers": raw_relevant_headers,
        },
        "authentication": {
            "spf": auth_results.get("spf"),
            "dkim": auth_results.get("dkim"),
            "dmarc": auth_results.get("dmarc"),
        },
        "indicators": {
            "ips": ips,
            "domains": domains,
            "urls": url_analysis,
            "attachments": attachments,
        },
        "earliest_observed_source": earliest,
        "anomalies": anomalies,
        "forensics_summary": {
            "anomaly_count": count,
            "risk_level": risk_level,
            "note": ("Evidence strength only, not a verdict. AI Detection "
                      "(Member 2) produces the actual classification."),
        },
    }
