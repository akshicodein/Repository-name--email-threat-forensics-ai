"""
main.py
Run API:  uvicorn main:app --reload --port 8001
Run CLI:  python main.py path/to/email.eml
"""
import sys
import json
import tempfile

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse

import parser
import headers as headers_mod
import authentication
import indicators
import attachments as attachments_mod
import report


def run_pipeline(eml_path):
    msg = parser.parse_eml(eml_path)
    email_fields = parser.extract_basic_headers(msg)
    raw_relevant = parser.extract_raw_relevant_headers(msg)
    body = parser.extract_body(msg)
    raw_attachments = parser.extract_attachments(msg)

    auth_results = authentication.parse_authentication_results(msg)
    chain = headers_mod.parse_received_chain(msg)

    searchable_text = f"{body['plain']} {body['html']} {email_fields.get('from','')}"
    ips = indicators.extract_ips(searchable_text)
    domains = indicators.extract_domains(searchable_text)
    urls = indicators.extract_urls(searchable_text)
    url_analysis = [indicators.analyze_url(u) for u in urls]
    attachment_results = attachments_mod.analyze_attachments(raw_attachments)

    anomalies = headers_mod.detect_anomalies(email_fields, auth_results, chain)

    return report.build_report(
        email_fields, raw_relevant, chain, auth_results,
        ips, domains, url_analysis, attachment_results, anomalies,
    )


app = FastAPI(title="Member 1 - Email Forensics Engine")


@app.post("/parse-email")
async def parse_email(file: UploadFile = File(...)):
    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name
    result = run_pipeline(tmp_path)
    return JSONResponse(content=result)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_email.eml>")
        sys.exit(1)
    result = run_pipeline(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))
