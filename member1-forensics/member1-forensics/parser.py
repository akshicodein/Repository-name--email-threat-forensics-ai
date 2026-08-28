"""
parser.py
Raw .eml -> structured Python data: headers, body, attachments.
"""
from email import policy
from email.parser import BytesParser


def parse_eml(file_path):
    with open(file_path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def _split_addr_list(header_value):
    if not header_value:
        return []
    return [a.strip() for a in header_value.split(",") if a.strip()]


def extract_basic_headers(msg):
    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "cc": _split_addr_list(msg.get("Cc", "")),
        "bcc": _split_addr_list(msg.get("Bcc", "")),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "sender": msg.get("Sender", ""),
        "mime_version": msg.get("MIME-Version", ""),
        "content_type": msg.get_content_type(),
    }


def extract_raw_relevant_headers(msg):
    fields = ["From", "Reply-To", "Return-Path", "Message-ID",
              "Authentication-Results", "DKIM-Signature", "Sender",
              "X-Originating-IP"]
    return {f: msg.get(f, "") for f in fields if msg.get(f) is not None}


def extract_body(msg):
    plain_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            if ct == "text/plain" and not plain_body:
                plain_body = part.get_content()
            elif ct == "text/html" and not html_body:
                html_body = part.get_content()
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plain_body = msg.get_content()
        elif ct == "text/html":
            html_body = msg.get_content()
    return {"plain": plain_body or "", "html": html_body or ""}


def extract_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename or "attachment" in disp:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "_raw": payload,
                })
    return attachments
