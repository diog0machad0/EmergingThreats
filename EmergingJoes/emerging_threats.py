"""Customer-based emerging threat analysis — runs during summarization."""

import json
import logging
import re
import time

from cost_tracker import cost_tracker
from database import (
    get_customers,
    get_connection,
    save_emerging_threat_analysis,
)
from llm_client import call_llm, get_model_name, has_api_key
from tech_matching import find_tech_in_text

logger = logging.getLogger(__name__)

# Match if ANY dimension hits (OR logic), article must describe threat activity.
VALID_DIMENSIONS = ("company", "country", "business", "affiliate", "tech_stack")

_THREAT_CONTEXT = (
    "attack", "breach", "ransomware", "exploit", "campaign", "compromised",
    "malware", "phishing", "threat actor", "apt", "cve-", "zero-day", "zero day",
    "data leak", "leak", "exposed", "extortion", "botnet", "backdoor", "infostealer",
    "stolen", "hack", "credentials", "password",
)

_REGIONAL_TERMS = {
    "portugal": ("portugal", "portuguese", "lusophone", "lusophone", "iberian", "iberia", "portugues"),
    "united kingdom": ("united kingdom", " uk ", " u.k.", "britain", "british", "english", " uk,"),
}

_BUSINESS_TERMS = (
    "insurance", "insurer", "seguros", "underwriting", "policyholder",
    "betting", "gaming", "gambling", "casino", "sportsbook", "wagering", "bookmaker",
)

_OUTLOOK_PROMPT = """You are a threat intelligence analyst. The article below has already been matched
to customers by deterministic rules. For each hit, write brief JSON enrichment only.

Each hit lists exactly what matched: matched_tech, matched_affiliates and
matched_business_terms. Ground your evidence in those values only. Never claim
the customer uses a product that is not in matched_tech, and do not invent a
reason for the match. If the matched values look unrelated to the article, say
the match is weak instead of justifying it.

Respond ONLY with valid JSON:
{
  "hits": [
    {
      "customer_id": 1,
      "match_evidence": "One sentence: what happened in the article and which OR-criteria matched.",
      "distribution_outlook": "1-3 sentences: how this threat may spread or impact this customer next."
    }
  ]
}

Be factual. No generic security advice. No hypothetical 'could benefit' language."""


def _is_rate_limit_error(exc):
    name = type(exc).__name__
    msg = str(exc).lower()
    return name == "RateLimitError" or "429" in msg or "rate limit" in msg


def _text_blob(title, content):
    return f"{title}\n{content}".lower()


def _has_threat_context(content_lower):
    return any(term in content_lower for term in _THREAT_CONTEXT)


def _find_affiliate_in_text(content_lower, affiliates):
    matched = []
    for aff in affiliates:
        key = aff.lower().strip()
        if not key:
            continue
        if key in content_lower:
            matched.append(aff)
            continue
        tokens = [t for t in re.split(r"[\s–\-/(),]+", key) if len(t) >= 4 and t not in ("companhia", "limited", "group")]
        if len(tokens) >= 1 and tokens[0] in content_lower:
            if len(tokens) == 1 or tokens[1] in content_lower:
                matched.append(aff)
    return list(dict.fromkeys(matched))


def _country_terms(country):
    country_l = country.lower().strip()
    terms = {country_l}
    for key, regional in _REGIONAL_TERMS.items():
        if key in country_l or country_l in key:
            terms.update(regional)
    return terms


def _country_match(content_lower, country):
    return any(term in content_lower for term in _country_terms(country))


def _company_match(content, content_lower, name):
    """Customer name appears in the article as a proper noun.

    A single-word name is matched case-sensitively against the original text,
    because company names are not always distinctive words: "Evoke" is an
    ordinary English verb, and matching it case-insensitively flagged articles
    about unrelated companies as naming the customer. Multi-word names are
    specific enough to match regardless of case.
    """
    raw = (name or "").strip()
    if not raw:
        return False
    if len(raw.split()) > 1:
        return bool(re.search(
            rf"(?<![a-z0-9]){re.escape(raw.lower())}(?![a-z0-9])", content_lower
        ))
    return bool(re.search(
        rf"(?<![A-Za-z0-9]){re.escape(raw)}(?![A-Za-z0-9])", content
    ))


def _business_match(content_lower, business_text):
    blob = business_text.lower()
    terms = [t for t in _BUSINESS_TERMS if t in blob]
    return [t for t in terms if t in content_lower]


def _build_evidence(customer_name, dims, matched_tech, matched_affiliates, country):
    parts = []
    if "company" in dims:
        parts.append(f"{customer_name} is named in the article")
    if "country" in dims:
        parts.append(f"the incident involves {country} or its nationals/regional scope")
    if "business" in dims:
        parts.append("the customer's industry sector is referenced")
    if "affiliate" in dims:
        parts.append(f"affiliate(s) mentioned: {', '.join(matched_affiliates[:3])}")
    if "tech_stack" in dims:
        parts.append(f"technology referenced: {', '.join(matched_tech[:3])}")
    return "; ".join(parts) + "."


def _compute_or_hits(title, content, customers):
    """Deterministic OR matching against customer profile fields."""
    blob = _text_blob(title, content)
    if not _has_threat_context(blob):
        return []
    original = f"{title}\n{content}"

    hits = []
    for customer in customers:
        dims = []
        matched_tech = find_tech_in_text(blob, customer.get("known_tech_stack") or [])
        matched_affiliates = _find_affiliate_in_text(blob, customer.get("known_affiliates") or [])
        matched_business = _business_match(blob, customer.get("business") or "")
        country = customer.get("country") or ""

        if _company_match(original, blob, customer["name"]):
            dims.append("company")
        if _country_match(blob, country):
            dims.append("country")
        if matched_business:
            dims.append("business")
        if matched_affiliates:
            dims.append("affiliate")
        if matched_tech:
            dims.append("tech_stack")

        if not dims:
            continue

        hits.append({
            "customer_id": customer["id"],
            "customer_name": customer["name"],
            "match_dimensions": dims,
            "matched_tech": matched_tech,
            "matched_affiliates": matched_affiliates,
            "matched_business_terms": matched_business,
            "match_evidence": _build_evidence(
                customer["name"], dims, matched_tech, matched_affiliates, country
            ),
            "distribution_outlook": "",
        })

    return hits


def _enrich_hits_with_llm(title, content, hits):
    """Optional LLM pass for richer evidence and distribution outlook."""
    if not hits or not has_api_key():
        return hits

    max_chars = 6000
    body = content[:max_chars] if len(content) > max_chars else content
    user_message = json.dumps({
        "article_title": title,
        "article_content": body,
        # The concrete values are required, not just the dimension names. Given
        # only "tech_stack", the model invents a plausible reason ("the customer
        # uses Orkes Conductor") instead of reporting what actually matched.
        "hits": [
            {"customer_id": h["customer_id"], "customer_name": h["customer_name"],
             "match_dimensions": h["match_dimensions"],
             "matched_tech": h["matched_tech"],
             "matched_affiliates": h["matched_affiliates"],
             "matched_business_terms": h["matched_business_terms"]}
            for h in hits
        ],
    }, indent=2)

    for attempt in range(2):
        try:
            content_str, it, ot, cc, cr = call_llm(
                _OUTLOOK_PROMPT,
                [{"role": "user", "content": user_message}],
                temperature=0.2,
                max_tokens=800,
                json_mode=True,
            )
            cost_tracker.add_tokens(it, ot, cc, cr)
            data = json.loads(content_str)
            by_id = {h["customer_id"]: h for h in data.get("hits") or []}
            for hit in hits:
                extra = by_id.get(hit["customer_id"], {})
                if extra.get("match_evidence"):
                    hit["match_evidence"] = extra["match_evidence"].strip()
                if extra.get("distribution_outlook"):
                    hit["distribution_outlook"] = extra["distribution_outlook"].strip()
            return hits
        except Exception as e:
            if _is_rate_limit_error(e):
                time.sleep(2 ** attempt)
            else:
                logger.warning(f"LLM enrichment skipped: {e}")
                break
    return hits


def analyze_customer_threats(title, content):
    """Match article to customers using OR logic on profile fields.

    Returns:
        List of hit dicts, or None if skipped (no API key — still runs deterministic;
        None only on hard failure paths). Empty list if no threat context or no matches.
    """
    customers = get_customers()
    if not customers:
        return []

    hits = _compute_or_hits(title, content, customers)
    if hits and has_api_key():
        hits = _enrich_hits_with_llm(title, content, hits)
    return hits


def analyze_and_store_customer_threats(article_id, title, content, executive_summary=None):
    """Run customer threat analysis and persist results for an article.

    Upserts so that an analyst's triage_status survives re-analysis; deleting
    the row first would drop the analyst back into the queue.
    """
    del executive_summary
    hits = analyze_customer_threats(title, content)
    if hits is None:
        return False
    save_emerging_threat_analysis(
        article_id=article_id,
        hits=hits,
        model_used=get_model_name() if has_api_key() else "deterministic",
    )
    if hits:
        logger.info(f"  Emerging threats: {len(hits)} customer hit(s) for article {article_id}")
    else:
        logger.info(f"  Emerging threats: no customer matches for article {article_id}")
    return True


def _articles_for_threat_reanalysis(limit=10):
    """Summarized articles missing analysis or with zero hits (for backfill)."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.id, a.title, a.content_raw
        FROM articles a
        JOIN summaries sm ON sm.article_id = a.id
        LEFT JOIN emerging_threat_analyses eta ON eta.article_id = a.id
        WHERE sm.model_used IS NOT NULL AND sm.model_used != 'failed'
          AND a.content_raw IS NOT NULL AND a.content_raw != ''
          AND (eta.id IS NULL OR eta.hits_json = '[]' OR json_array_length(eta.hits_json) = 0)
        ORDER BY a.fetched_date DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def analyze_missing_threats(limit=10):
    """Backfill or re-run emerging threat analysis on articles with no hits."""
    articles = _articles_for_threat_reanalysis(limit=limit)
    processed = 0
    for article in articles:
        ok = analyze_and_store_customer_threats(
            article["id"],
            article["title"],
            article["content_raw"] or "",
        )
        if ok:
            processed += 1
    return processed
