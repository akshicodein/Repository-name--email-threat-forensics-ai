"""
attachments.py
Attachment forensics: metadata + SHA-256 + suspicious static indicators.
SAFE STATIC ANALYSIS ONLY - never execute, open, or run macros.
"""
import hashlib

_EXECUTABLE_EXT = {"exe", "bat", "cmd", "scr", "js", "vbs", "ps1", "jar", "msi", "com"}
_MACRO_EXT = {"docm", "xlsm", "pptm"}
_ARCHIVE_EXT = {"zip", "rar", "7z", "iso"}


def _sha256(raw_bytes):
    return hashlib.sha256(raw_bytes).hexdigest()


def _extensions(filename):
    parts = filename.lower().split(".")
    return parts[1:] if len(parts) > 1 else []


def analyze_attachments(raw_attachments):
    results = []
    for att in raw_attachments:
        raw = att.get("_raw", b"")
        filename = att.get("filename") or "unknown"
        exts = _extensions(filename)
        final_ext = exts[-1] if exts else ""

        flags = []
        if len(exts) >= 2:
            flags.append("double_extension")
        if final_ext in _EXECUTABLE_EXT:
            flags.append("executable_file_type")
        if final_ext in _MACRO_EXT:
            flags.append("macro_enabled_document")
        if final_ext in _ARCHIVE_EXT:
            flags.append("unexpected_archive")

        results.append({
            "filename": filename,
            "extension": final_ext,
            "content_type": att.get("content_type"),
            "size_bytes": att.get("size_bytes", 0),
            "sha256": _sha256(raw) if raw else None,
            "suspicious_flags": flags,
        })
    return results
