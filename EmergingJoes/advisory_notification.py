"""Security Vulnerability Notification — the distribution message format.

The LLM only extracts field *values*; the layout below is rendered in code.
Letting the model emit the whole message invites reordered, renamed, or dropped
lines, and this notification is a client-facing deliverable whose shape is
fixed.
"""

import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# Canonical template. Kept verbatim so the rendered output below can be
# diffed against what the business signed off on.
NOTIFICATION_TEMPLATE = """Security Vulnerability Notification

Advisory Date: [DD Month YYYY]
Vulnerability Name: [Vulnerability or advisory name]
Vendor / Product: [Vendor and affected product]
CVE(s): [CVE ID(s)]
Advisory ID: [Vendor advisory ID / N/A]
Severity: [Critical / High / Medium / Low]
Affected Versions: [Affected version(s)]
Fixed Version: [Fixed version / Not available]

Description:
[Briefly describe the vulnerability, exploitation requirements, and potential impact.]

Recommendations:
\u2022 [Required patch, upgrade, mitigation, or validation action]
\u2022 [Priority and requested completion date]
Attachments:
\u2022 [Advisory filename].pdf \u2014 Security advisory
"""

# Threat intelligence advisories have no CVE and no version numbers, so the
# same layout is reused minus those fields and with its own heading.
TI_NOTIFICATION_TEMPLATE = """Threat Intelligence Notification

Advisory Date: [DD Month YYYY]
Threat Name: [Threat, campaign, or actor name]
Vendor / Product: [Affected vendor, product, or technology]
Advisory ID: [Vendor or CERT advisory ID / N/A]
Severity: [Critical / High / Medium / Low]

Description:
[Briefly describe the threat, how it is delivered, and potential impact.]

Recommendations:
\u2022 [Required detection, mitigation, or validation action]
\u2022 [Priority and requested completion date]
Attachments:
\u2022 [Advisory filename].pdf \u2014 Security advisory
"""

NOT_AVAILABLE = "N/A"
SEVERITIES = ("Critical", "High", "Medium", "Low")

TI_KIND = "threat_intelligence"

# (label, field key, default) in render order.
_VULN_LAYOUT = (
    ("Vulnerability Name", "vulnerability_name", NOT_AVAILABLE),
    ("Vendor / Product", "vendor_product", NOT_AVAILABLE),
    ("CVE(s)", "cves", NOT_AVAILABLE),
    ("Advisory ID", "advisory_id", NOT_AVAILABLE),
    ("Severity", "severity", NOT_AVAILABLE),
    ("Affected Versions", "affected_versions", NOT_AVAILABLE),
    ("Fixed Version", "fixed_version", "Not available"),
)

_TI_LAYOUT = (
    ("Threat Name", "vulnerability_name", NOT_AVAILABLE),
    ("Vendor / Product", "vendor_product", NOT_AVAILABLE),
    ("Advisory ID", "advisory_id", NOT_AVAILABLE),
    ("Severity", "severity", NOT_AVAILABLE),
)


def is_threat_intelligence(advisory):
    return (advisory or {}).get("kind") == TI_KIND


def _layout(advisory):
    return _TI_LAYOUT if is_threat_intelligence(advisory) else _VULN_LAYOUT


def _heading(advisory):
    return ("Threat Intelligence Notification" if is_threat_intelligence(advisory)
            else "Security Vulnerability Notification")

# Remediation windows by severity, used to fill the "priority and requested
# completion date" bullet. A deterministic table beats asking the model to
# invent a date, which produced inconsistent deadlines across advisories.
REMEDIATION_DAYS = {"Critical": 7, "High": 14, "Medium": 30, "Low": 90}
DEFAULT_REMEDIATION_DAYS = 30

_FIELD_KEYS = (
    "vulnerability_name",
    "vendor_product",
    "cves",
    "advisory_id",
    "severity",
    "affected_versions",
    "fixed_version",
    "description",
)

_EXTRACTION_SYSTEM = (
    "You are a vulnerability analyst preparing a client notification. "
    "You extract facts that are present in the supplied advisory and never "
    "invent version numbers, identifiers, or severities."
)

_TI_EXTRACTION_SYSTEM = (
    "You are a threat intelligence analyst preparing a client notification. "
    "You extract facts that are present in the supplied advisory and never "
    "invent actor names, identifiers, or severities."
)

_EXTRACTION_PROMPT = """Extract the fields below from this security advisory.

Return a JSON object with exactly these keys:
- "vulnerability_name": short descriptive name of the vulnerability (not the CVE ID).
- "vendor_product": vendor and affected product, e.g. "Cisco Identity Services Engine (ISE)".
- "cves": all CVE IDs covered, comma-separated.
- "advisory_id": the vendor's own advisory identifier (e.g. "cisco-sa-ise-injection-vE4ebbf9"). Use "N/A" if the advisory does not state one.
- "severity": exactly one of Critical, High, Medium, Low. Use "N/A" if the advisory does not state one.
- "affected_versions": affected version(s) or build range.
- "fixed_version": the fixed/patched version. Use "Not available" if no fix has shipped.
- "description": 2-4 sentences covering what the vulnerability is, what an attacker needs in order to exploit it (authentication, adjacency, user interaction), and the impact if exploited.
- "recommendations": array of 1-3 short imperative action strings (patch, upgrade, mitigation, or validation steps). Do not include a deadline or priority — that is added separately.

Use "N/A" for any field the advisory genuinely does not state. Do not guess.
Write plain text: no markdown, no bullet characters, no surrounding quotes.

ADVISORY CONTEXT
Title: {title}
CVE from triage: {cve_id}
Affected technology from triage: {technology}

ADVISORY DOCUMENT
{markdown}
"""

_TI_EXTRACTION_PROMPT = """Extract the fields below from this threat intelligence advisory.

Return a JSON object with exactly these keys:
- "vulnerability_name": the threat, campaign, malware family, or actor name.
- "vendor_product": the vendor, product, or technology the threat targets.
- "advisory_id": a vendor, CERT, or government advisory identifier if the advisory cites one (e.g. "AA24-109A"). Use "N/A" otherwise.
- "severity": exactly one of Critical, High, Medium, Low, reflecting the risk this threat poses. Use "N/A" if the advisory does not support a rating.
- "description": 2-4 sentences covering what the threat is, how it is delivered or gains access, and the impact on a compromised organisation.
- "recommendations": array of 1-3 short imperative actions (detection, hunting, hardening, or validation steps). Do not include a deadline or priority — that is added separately.

Use "N/A" for any field the advisory genuinely does not state. Do not guess.
Write plain text: no markdown, no bullet characters, no surrounding quotes.

ADVISORY CONTEXT
Title: {title}
Affected technology from triage: {technology}

ADVISORY DOCUMENT
{markdown}
"""


def _esc(value):
    """Escape the three characters Slack reserves in message text."""
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _clean(value, default=NOT_AVAILABLE):
    """Normalize a model-supplied value to a single clean line."""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v).strip() for v in value if str(v).strip())
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = text.strip("*_`").strip()
    if not text or text.lower() in ("none", "null", "unknown", "n/a", "na", "-"):
        return default
    return text


def _normalize_severity(value):
    text = _clean(value, NOT_AVAILABLE)
    for level in SEVERITIES:
        if text.lower() == level.lower():
            return level
    # Models sometimes answer "Critical (9.8 CVSS)" — accept a leading match.
    for level in SEVERITIES:
        if text.lower().startswith(level.lower()):
            return level
    return NOT_AVAILABLE


def _advisory_date(advisory):
    raw = (advisory or {}).get("created_date")
    if raw:
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "").strip())
        except ValueError:
            pass
    return datetime.now()


def format_advisory_date(value):
    """Render a datetime as ``DD Month YYYY`` without platform-specific codes."""
    return f"{value.day:02d} {value.strftime('%B')} {value.year}"


def _priority_bullet(severity, advisory_date):
    """Build the 'priority and requested completion date' bullet."""
    days = REMEDIATION_DAYS.get(severity, DEFAULT_REMEDIATION_DAYS)
    due = advisory_date + timedelta(days=days)
    priority = severity if severity in SEVERITIES else "Standard"
    return (
        f"Priority: {priority} \u2014 please confirm remediation or a documented "
        f"mitigation by {format_advisory_date(due)}."
    )


def read_advisory_markdown(advisory, limit=14000):
    """Return the generated advisory markdown, or '' when unavailable."""
    path = (advisory or {}).get("markdown_path")
    if not path:
        return ""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        logger.warning("Could not read advisory markdown %s: %s", path, e)
        return ""
    return text[:limit]


def fallback_fields(advisory):
    """Fields derivable without the LLM, so distribution never hard-fails."""
    advisory = advisory or {}
    action = (
        "Review the attached advisory and assess exposure."
        if is_threat_intelligence(advisory)
        else "Review the attached advisory and apply the vendor fix."
    )
    return {
        "vulnerability_name": _clean(advisory.get("title")),
        "vendor_product": _clean(advisory.get("technology")),
        "cves": _clean(advisory.get("cve_id")),
        "advisory_id": NOT_AVAILABLE,
        "severity": NOT_AVAILABLE,
        "affected_versions": NOT_AVAILABLE,
        "fixed_version": NOT_AVAILABLE,
        "description": _clean(
            advisory.get("title"),
            "See the attached advisory for full details.",
        ),
        "recommendations": [action],
    }


def extract_fields(advisory, markdown_text):
    """Ask the LLM to pull notification fields out of the advisory document.

    Raises:
        Exception on API or parse failure — the caller falls back.
    """
    from cost_tracker import cost_tracker
    from llm_client import call_llm

    advisory = advisory or {}
    ti = is_threat_intelligence(advisory)
    template = _TI_EXTRACTION_PROMPT if ti else _EXTRACTION_PROMPT
    kwargs = {
        "title": advisory.get("title") or NOT_AVAILABLE,
        "technology": advisory.get("technology") or NOT_AVAILABLE,
        "markdown": markdown_text or "(advisory document unavailable)",
    }
    if not ti:
        kwargs["cve_id"] = advisory.get("cve_id") or NOT_AVAILABLE
    prompt = template.format(**kwargs)

    content, it, ot, cc, cr = call_llm(
        _TI_EXTRACTION_SYSTEM if ti else _EXTRACTION_SYSTEM,
        [{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=1200,
        json_mode=True,
    )
    cost_tracker.add_tokens(it, ot, cc, cr)

    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("LLM returned JSON that is not an object")

    fields = {key: _clean(data.get(key)) for key in _FIELD_KEYS}
    fields["severity"] = _normalize_severity(data.get("severity"))
    fields["fixed_version"] = _clean(data.get("fixed_version"), "Not available")

    recs = data.get("recommendations")
    if isinstance(recs, str):
        recs = [recs]
    cleaned = [_clean(r, "") for r in (recs or [])]
    fields["recommendations"] = [r for r in cleaned if r]
    return fields


def merge_fields(primary, fallback):
    """Fill gaps in LLM output from the values we already hold in the DB."""
    merged = dict(primary or {})
    for key, value in (fallback or {}).items():
        current = merged.get(key)
        if key == "recommendations":
            if not current:
                merged[key] = value
            continue
        if not current or current == NOT_AVAILABLE:
            if value and value != NOT_AVAILABLE:
                merged[key] = value
    return merged


def render(fields, advisory, article_url=None):
    """Render the notification. Pure: no network, no config, no file reads."""
    advisory = advisory or {}
    fields = fields or {}
    date = _advisory_date(advisory)
    severity = _normalize_severity(fields.get("severity"))

    def value(key, default=NOT_AVAILABLE):
        return _esc(_clean(fields.get(key), default))

    lines = [
        f"*{_heading(advisory)}*",
        "",
        f"*Advisory Date:* {format_advisory_date(date)}",
    ]
    for label, key, default in _layout(advisory):
        rendered = _esc(severity) if key == "severity" else value(key, default)
        lines.append(f"*{label}:* {rendered}")

    lines.extend([
        "",
        "*Description:*",
        value("description", "See the attached advisory for full details."),
        "",
        "*Recommendations:*",
    ])

    actions = [a for a in (fields.get("recommendations") or []) if _clean(a, "")]
    if not actions:
        actions = [fallback_fields(advisory)["recommendations"][0]]
    lines.extend(f"\u2022 {_esc(a)}" for a in actions)
    lines.append(f"\u2022 {_esc(_priority_bullet(severity, date))}")

    # No blank line before Attachments — matches the approved template.
    lines.append("*Attachments:*")
    pdf_name = advisory.get("pdf_filename") or "advisory.pdf"
    lines.append(f"\u2022 {_esc(pdf_name)} \u2014 Security advisory")

    if article_url:
        lines.append("")
        lines.append(f"*Source:* <{_esc(article_url)}>")

    return "\n".join(lines)


def build(advisory, article_url=None, use_llm=True):
    """Build the notification text for an advisory.

    Falls back to DB-derived fields whenever the LLM is unconfigured or fails:
    a degraded notification with N/A fields beats blocking distribution of an
    advisory that has already been generated.

    Returns:
        (text, used_llm) tuple.
    """
    fallback = fallback_fields(advisory)
    fields, used_llm = fallback, False

    if use_llm:
        try:
            from llm_client import has_api_key

            if has_api_key():
                extracted = extract_fields(advisory, read_advisory_markdown(advisory))
                fields = merge_fields(extracted, fallback)
                used_llm = True
            else:
                logger.info("No LLM key configured; notification uses advisory metadata only")
        except Exception as e:
            logger.warning("Notification field extraction failed, using fallback: %s", e)

    return render(fields, advisory, article_url), used_llm
