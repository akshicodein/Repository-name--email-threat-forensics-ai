"""
indicators.py
IOC extraction: IPs, domains, URLs (with static analysis).
Static only - never visit or execute extracted URLs.
"""
import re
from urllib.parse import urlparse

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

_KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
_LOGIN_KEYWORDS = ("login", "signin", "verify", "account", "secure", "update", "password")


def extract_ips(text):
    return sorted(set(_IP_RE.findall(text or "")))


def extract_domains(text):
    return sorted(set(d.lower() for d in _DOMAIN_RE.findall(text or "")))


def extract_urls(text):
    return sorted(set(_URL_RE.findall(text or "")))


def analyze_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return {
        "url": url,
        "scheme": parsed.scheme,
        "host": host,
        "domain": host,
        "path": parsed.path,
        "query": parsed.query,
        "is_ip_based": bool(_IP_RE.fullmatch(host)),
        "is_shortener": host in _KNOWN_SHORTENERS,
        "is_punycode": host.startswith("xn--") or ".xn--" in host,
        "has_login_like_path": any(k in parsed.path.lower() for k in _LOGIN_KEYWORDS),
    }
