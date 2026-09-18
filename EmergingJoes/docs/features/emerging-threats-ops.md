# Emerging Threats (operational)

Analyst-facing queues that sit on top of summarized feed articles. Page: `/emerging-threats`.

## Tabs

### 1. Threat Intelligence

Customer-footprint matches produced by `emerging_threats.py` (also invoked during summarization).

- Match dimensions (OR): company, country, business, affiliate, tech_stack  
- Requires threat-context language in the article  
- LLM enrichment: match evidence + distribution outlook  
- Stored in `emerging_threat_analyses` (`hits_json`)  
- **Create advisory** → `POST /api/emerging-threats/advisory` → kind `threat_intelligence`  

## Tech-stack matching

Both queues share one implementation, `tech_matching.find_tech_in_text()`, so they
cannot drift apart. A stack entry matches when:

1. its full name appears literally in the article, or
2. one of its **distinctive** tokens appears there.

Both checks are boundary-anchored, so a term only matches where it is not part of
a longer word. This is not optional: `AWS` occurs inside "flaws" and `Git` inside
"digit", "legit" and "github", which between them appear in most security
articles. The anchors use lookarounds rather than `\b` because product names like
`Notepad++` end in a non-word character, where `\b` would require a following
word character and never match.

Both edges are anchored even when the entry itself begins or ends with
punctuation. Anchoring only the alphanumeric edge let `.NET` match the hostname
`router.example.net` in an article's example SSH command.

A token is **not** distinctive when it is:

- a generic word — `security`, `networks`, `enterprise`, `storage`,
  `configuration`, `exchange`, `power`, `sql`, …
- a product-category acronym — `vpn`, `siem`, `edr`, `ngfw`, …
- shared across one vendor's product line — `defender` cannot pick out which of
  six `... Defender ...` products an article means
- a broad vendor name — `microsoft`, `cisco`, `vmware`, … An article about Cisco
  Webex is not a Cisco ISE article, so each Cisco product must be named. A vendor
  name still matches when the stack entry is nothing but the vendor (`Citrix`).
- ordinary English — `for`, `new`, `red`, `cross`, `connect`, … Without these,
  `Microsoft Defender for Endpoint` matches every article containing "for".
- a bare number — otherwise `Windows Server 2025` matches any mention of 2025.

When every token of an entry is excluded, the entry still matches on its full
name, which is usually how articles write it anyway ("Microsoft 365", "F5
BIG-IP", "Red Hat", "Cisco IOS XE").

**Write stack entries as product names.** `Ivanti Connect Secure` or `RouterOS`
match well; a bare category like `VPN` will never match on its own. Name the
product, not the vendor (`Cisco ISE`, not `Cisco`), and prefer the spelling
articles use — `.NET Framework` over `Microsoft .NET Framework`, since `net` on
its own is not distinctive.

Some false positives are irreducible without corpus statistics: "a federal agent
shows up at a **rancher's** gate" matches a `SUSE Rancher` entry. Vendor-named
entries also match industry news about the vendor (funding, acquisitions) rather
than vulnerabilities in it. The LLM enrichment step, not the matcher, is what
filters those out.

## Company-name matching

A single-word customer name is matched **case-sensitively** against the original
article text; multi-word names are matched case-insensitively. Customer names are
not always distinctive words — `Evoke` is an ordinary English verb, and matching
it case-insensitively marked articles about unrelated companies as naming the
customer, which is the most misleading thing the queue can tell an analyst.

## LLM enrichment is given the matched values

The enrichment payload includes `matched_tech`, `matched_affiliates` and
`matched_business_terms`, not just the dimension names. Told only that
`tech_stack` matched, the model invented a justification — it reported that a
customer "uses Orkes Conductor" on an article where the matcher had actually hit
`Python`. The prompt also instructs it to call a match weak rather than
rationalise one, so thin country-only matches now say so.

### 2. Vulnerabilities

CVE + customer tech-stack co-occurrence (`vulnerability_threats.py`).

- Hit fields: `cve_id`, `matched_tech`, `customer_id`, evidence  
- **Create advisory** → `POST /api/vulnerabilities/advisory` → kind `vulnerability`  
- Requires valid `CVE-YYYY-NNNN…` and non-empty matched tech  

### 3. Advisories

DB-backed index of generated reports. See [advisories.md](advisories.md).

## Triage queue

Both TI and Vulnerability lists default to `triage_status=pending`.

| Status | Meaning |
|--------|---------|
| `pending` | In analyst queue (default view) |
| `triaged` | Reviewed; hidden from queue unless filter = Triaged/All |

- UI: **Mark as Triaged** / **Restore to queue**  
- API: `POST .../triage` with `{ "triage_status": "triaged" }` — the path segment is
  the **`article_id`**, not the `analysis_id` returned in the queue payload  
- Re-running analysis **preserves** triage (upsert does not overwrite status, and
  the analysis row must not be deleted first — doing so resets it to `pending`)  
- Triage does **not** delete articles, summaries, hits, or advisories  

Filter dropdown: Queue (untriaged) | Triaged | All.

## Backfill

- `POST /api/emerging-threats/analyze-missing` — summarized articles without TI analysis  
- `POST /api/vulnerabilities/analyze-missing` — summarized articles without vuln analysis  

## Customers

Configure footprint on `/customers`. Empty customer table may be seeded by `seed_default_customers()` on init.
