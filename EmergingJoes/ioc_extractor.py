"""Extract IOCs from article text and LLM summary output."""

import json
import logging
import re

from cost_tracker import cost_tracker
from llm_client import call_llm, has_api_key

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_IPV6_RE = re.compile(
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)

# TLDs that are usually file/code tokens, not network domains
_INVALID_TLDS = {
    "dll", "exe", "bin", "png", "jpg", "jpeg", "gif", "py", "hex", "open",
    "append", "unpack", "pack", "decrypt", "new", "argv", "exit", "tobytes",
    "cipher", "shellcode", "local", "test", "json", "xml", "css", "js",
}

_VALID_NETWORK_TLDS = {
    "com", "net", "org", "io", "ua", "ru", "cn", "de", "fr", "uk", "co", "info",
    "biz", "me", "app", "dev", "edu", "gov", "mil", "int", "eu",
}

# RFC 2606 / RFC 6761 names reserved for documentation. Articles use these in
# example commands ("ssh router.example.net"), and exporting them to MISP would
# publish indicators that can never match real activity.
_RESERVED_DOMAIN_SUFFIXES = (
    ".example.com", ".example.net", ".example.org",
    ".invalid", ".example", ".test", ".localhost", ".local",
)

_RESERVED_DOMAINS = {
    "localhost", "example.com", "example.net", "example.org", "example.edu",
    "domain.com", "yourdomain.com", "mydomain.com", "site.com",
}

_MISP_TYPE = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email-src",
}


def _dedupe_iocs(items):
    seen = set()
    out = []
    for item in items:
        key = (item["type"], item["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _is_network_domain(domain):
    d = domain.lower().rstrip(".")
    if d in _RESERVED_DOMAINS or d.endswith(_RESERVED_DOMAIN_SUFFIXES):
        return False
    parts = d.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld in _INVALID_TLDS:
        return False
    if tld not in _VALID_NETWORK_TLDS:
        return False
    return True


def extract_iocs_regex(text):
    """Deterministic IOC extraction from raw text."""
    if not text:
        return []

    found = []
    for ip in _IPV4_RE.findall(text):
        found.append({"type": "ipv4", "value": ip, "source": "regex"})
    for ip in _IPV6_RE.findall(text):
        found.append({"type": "ipv6", "value": ip, "source": "regex"})
    for url in _URL_RE.findall(text):
        found.append({"type": "url", "value": url.rstrip(".,;)"), "source": "regex"})
    for dom in _DOMAIN_RE.findall(text):
        d = dom.lower().rstrip(".")
        if not _is_network_domain(d):
            continue
        found.append({"type": "domain", "value": d, "source": "regex"})
    for h in _SHA256_RE.findall(text):
        found.append({"type": "sha256", "value": h.lower(), "source": "regex"})
    for h in _SHA1_RE.findall(text):
        if len(h) == 40:
            found.append({"type": "sha1", "value": h.lower(), "source": "regex"})
    for h in _MD5_RE.findall(text):
        found.append({"type": "md5", "value": h.lower(), "source": "regex"})
    for em in _EMAIL_RE.findall(text):
        addr = em.lower()
        if not _is_network_domain(addr.rsplit("@", 1)[-1]):
            continue
        found.append({"type": "email", "value": addr, "source": "regex"})

    return _dedupe_iocs(found)


def extract_iocs_llm(title, content, apt_names, existing_iocs=None):
    """Use LLM to extract IOCs and campaign context for APT-tagged articles."""
    if not has_api_key():
        return {"iocs": [], "campaign": None, "context": None}

    existing = existing_iocs or []
    existing_str = json.dumps(existing[:30], indent=2) if existing else "[]"
    apt_list = ", ".join(apt_names)

    prompt = f"""Analyze this security article attributed to threat actor(s): {apt_list}.

Extract ONLY indicators of compromise (IOCs) explicitly present in the text — IPs, domains, URLs, file hashes, email addresses.
Also extract campaign name (if mentioned) and a 1-2 sentence operational context.

Article title: {title}

Article content (truncated):
{(content or '')[:10000]}

Already extracted by regex (verify, dedupe, add missing):
{existing_str}

Respond in JSON:
{{
  "campaign": "campaign name or null",
  "context": "brief operational context or null",
  "iocs": [
    {{"type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email", "value": "...", "comment": "optional context"}}
  ]
}}"""

    try:
        content_str, it, ot, cc, cr = call_llm(
            "You are a threat intelligence analyst extracting IOCs for MISP.",
            [{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=2000,
            json_mode=True,
        )
        cost_tracker.add_tokens(it, ot, cc, cr)
        data = json.loads(content_str)
        llm_iocs = []
        for ioc in data.get("iocs") or []:
            ioc_type = (ioc.get("type") or "").lower().strip()
            value = (ioc.get("value") or "").strip()
            if not value or ioc_type not in _MISP_TYPE:
                continue
            llm_iocs.append({
                "type": ioc_type,
                "value": value,
                "source": "llm",
                "comment": ioc.get("comment"),
            })
        merged = _dedupe_iocs((existing or []) + llm_iocs)
        return {
            "iocs": merged,
            "campaign": data.get("campaign"),
            "context": data.get("context"),
        }
    except Exception as e:
        logger.warning("LLM IOC extraction failed: %s", e)
        return {"iocs": existing or [], "campaign": None, "context": None}


def extract_article_iocs(title, content, summary_text=None, apt_names=None):
    """Combined regex + optional LLM IOC extraction."""
    blob = "\n".join(filter(None, [title, content, summary_text]))
    regex_iocs = extract_iocs_regex(blob)

    if apt_names and has_api_key():
        enriched = extract_iocs_llm(title, content, apt_names, regex_iocs)
        return enriched

    return {"iocs": regex_iocs, "campaign": None, "context": None}


def to_misp_attributes(iocs, default_comment=""):
    """Convert extracted IOC dicts to MISP attribute payloads."""
    attrs = []
    for ioc in iocs:
        misp_type = _MISP_TYPE.get(ioc["type"])
        if not misp_type:
            continue
        attrs.append({
            "type": misp_type,
            "value": ioc["value"],
            "comment": ioc.get("comment") or default_comment,
        })
    return attrs
