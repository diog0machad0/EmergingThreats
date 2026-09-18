"""Shared customer tech-stack matching for the TI and vulnerability queues.

Both queues must agree on what "this article mentions the customer's technology"
means, so the rule lives here rather than being reimplemented per queue.
"""

import re
from functools import lru_cache

# Words that occur inside product names but are far too common in security
# prose to identify a product on their own: "Splunk Enterprise Security" must
# not match an article that merely uses the word "security".
_GENERIC_TOKENS = frozenset({
    "access", "active", "analytics", "app", "apps", "big", "center", "centre",
    "cloud", "core", "data", "database", "desktop", "desktops", "directory",
    "edge", "email", "endpoint", "enterprise", "firewall", "gateway", "hybrid",
    "identity", "infrastructure", "mainframe", "manager", "management",
    "mobile", "monitor", "network", "networks", "online", "platform",
    "protection", "secure", "security", "server", "servers", "service",
    "services", "software", "solution", "solutions", "suite", "system",
    "systems", "virtual", "web", "workspace",
    # Product-category acronyms. These describe a class of product, not a
    # specific one: "Ivanti VPN" must not match every article saying "VPN".
    "api", "cdn", "crm", "daas", "dhcp", "dlp", "dns", "edr", "emm", "erp",
    "iam", "ids", "iot", "ips", "itsm", "ldap", "mdm", "mfa", "ndr", "ngfw",
    "pam", "san", "siem", "soar", "sso", "ssl", "tls", "vdi", "vpn", "waf",
    "xdr",
    # Product words that are also ordinary English or deployment jargon.
    # "Microsoft Teams" must not match "security teams", and "Windows 11"
    # should match the phrase rather than every mention of Windows.
    "admin", "agent", "appliance", "appliances", "automation", "backup",
    "client", "console", "content", "custom", "dashboard", "internet",
    "licensing", "logs", "office", "outlook", "portal", "print", "pro",
    "proxy", "release", "reporter", "reporting", "scripts", "shield",
    "store", "teams", "tools", "unified", "windows",
    # Shared by every product in a vendor's line, so they cannot say which one
    # an article means. A real stack can hold six "... Defender ..." products.
    "defender", "operations", "framework",
    # Everyday IT nouns, each observed matching unrelated articles: "storage"
    # via browser storage, "sql" via SQL injection, "exchange" via key
    # exchange, "ios" via Apple iOS in a Cisco IOS entry.
    "advisor", "configuration", "connect", "exchange", "ftp", "hat", "http",
    "https", "ios", "linux", "media", "net", "player", "power", "red", "sql",
    "storage",
    # Ordinary English. Without these, "Microsoft Defender for Endpoint"
    # matches every article containing the word "for".
    "all", "and", "any", "are", "but", "for", "from", "has", "her", "him",
    "his", "how", "its", "new", "not", "now", "old", "one", "only", "our",
    "out", "own", "per", "pre", "the", "them", "then", "they", "this", "two",
    "use", "via", "was", "were", "what", "when", "which", "who", "why",
    "will", "with", "you", "your", "cross", "next", "open", "real", "true",
})

# Years and other bare numbers: "Windows Server 2025" must not match every
# article that happens to mention 2025.
_NUMERIC_RE = re.compile(r"^[0-9]+$")

# Vendors with broad portfolios: the vendor name alone does not imply the
# specific product a customer runs (an article about Microsoft Teams is not an
# Active Directory article). These match only as part of a longer phrase, or
# when the stack entry names nothing but the vendor.
_BROAD_VENDOR_TOKENS = frozenset({
    "adobe", "akamai", "amazon", "apache", "apple", "atlassian", "aws",
    "azure", "beyondtrust", "broadcom", "brocade", "cisco", "citrix", "dell",
    "eclipse", "elastic", "forcepoint", "fortinet", "google", "hp", "hpe",
    "ibm", "imperva", "jfrog", "microsoft", "mozilla", "netapp", "nutanix",
    "oracle", "paessler", "sap", "splunk", "suse", "tenable", "veeam",
    "veritas", "vmware",
})

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9+./-]*")

_MIN_TOKEN_LEN = 3


@lru_cache(maxsize=4096)
def _bounded(term):
    """Match `term` only where it is not embedded in a longer word.

    Plain `in` checks are unusable here because "AWS" occurs inside "flaws",
    which appears in most security articles. \\b cannot be used directly either:
    product names such as "Notepad++" end in a non-word character, where \\b
    would demand a following word character and never match. Both edges are
    guarded even when the term itself starts or ends with punctuation, so the
    ".NET" entry does not match the host "router.example.net".
    """
    return re.compile(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])")


def find_tech_in_text(content_lower, tech_stack):
    """Return the tech-stack entries an article plausibly refers to.

    An entry matches when its full name appears, or when one of its distinctive
    tokens does. Both are matched only where they are not embedded in a longer
    word. Generic words, ordinary English, bare numbers and broad vendor names
    are not distinctive on their own, which is what keeps multi-word product
    names from matching ordinary security prose.

    Args:
        content_lower: Article title + body, already lowercased.
        tech_stack: Customer's known technology entries.

    Returns:
        The matching entries, in stack order, without duplicates.
    """
    matched = []
    for tech in tech_stack or []:
        key = (tech or "").strip().lower()
        if not key:
            continue

        if _bounded(key).search(content_lower):
            matched.append(tech)
            continue

        tokens = _TOKEN_RE.findall(key)
        distinctive = [
            t for t in tokens
            if len(t) >= _MIN_TOKEN_LEN
            and t not in _GENERIC_TOKENS
            and not _NUMERIC_RE.match(t)
            and (t not in _BROAD_VENDOR_TOKENS or len(tokens) == 1)
        ]
        if any(_bounded(t).search(content_lower) for t in distinctive):
            matched.append(tech)

    return list(dict.fromkeys(matched))
