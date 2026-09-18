"""Generate Scriba security advisories from CVE or threat-intelligence article context."""

import logging
import re
import subprocess
import sys
from pathlib import Path

from cost_tracker import cost_tracker
from llm_client import call_llm, get_model_name, has_api_key

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.I)

SCRIBA_ROOT = Path(__file__).resolve().parent.parent / "scriba"
SAMPLE_ADVISORY = SCRIBA_ROOT / "reports" / "sample_advisory.md"
REPORTS_DIR = SCRIBA_ROOT / "reports"
OUTPUT_DIR = SCRIBA_ROOT / "output"


def _slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:80] or "topic"


def advisory_base_name(cve_id, technology):
    """Filename stem: cve-2026-1234_microsoft-active-directory"""
    return f"{cve_id.lower()}_{_slugify(technology)}"


def ti_advisory_base_name(article_id, topic, customer_name=None):
    """Filename stem for threat-intelligence advisories."""
    parts = [f"ti-{int(article_id)}"]
    if customer_name:
        parts.append(_slugify(customer_name)[:40])
    parts.append(_slugify(topic)[:40])
    return "_".join(parts)


def advisory_paths(cve_id, technology):
    stem = advisory_base_name(cve_id, technology)
    md = REPORTS_DIR / f"{stem}.md"
    pdf = OUTPUT_DIR / f"{stem}.pdf"
    return stem, md, pdf


def ti_advisory_paths(article_id, topic, customer_name=None):
    stem = ti_advisory_base_name(article_id, topic, customer_name)
    md = REPORTS_DIR / f"{stem}.md"
    pdf = OUTPUT_DIR / f"{stem}.pdf"
    return stem, md, pdf


def _python_executable():
    for rel in (("bin", "python"), ("Scripts", "python.exe")):
        venv_py = SCRIBA_ROOT / ".venv" / Path(*rel)
        if venv_py.is_file():
            return str(venv_py)
    return sys.executable


def _strip_code_fence(md_text):
    md_text = (md_text or "").strip()
    if md_text.startswith("```"):
        md_text = re.sub(r"^```(?:markdown|md)?\n?", "", md_text)
        md_text = re.sub(r"\n?```$", "", md_text.strip())
    return md_text


def generate_advisory_markdown(cve_id, article_title, article_content, matched_tech):
    """Call LLM to produce advisory markdown following the Scriba sample template."""
    if not has_api_key():
        raise RuntimeError(
            "LLM API key required to generate advisories "
            "(configure OpenAI, Anthropic, or OpenRouter in Settings)"
        )

    if not SAMPLE_ADVISORY.is_file():
        raise FileNotFoundError(f"Sample advisory not found: {SAMPLE_ADVISORY}")

    sample_text = SAMPLE_ADVISORY.read_text(encoding="utf-8")
    content = (article_content or "")[:12000]

    user_prompt = f"""Take the sample advisory that is attached.

Now, do research regarding {cve_id} and fill output a markdown file that follows the template of the sample one I sent. Research must be done with the most recent data, no shortcuts, no backing down or doing just half steps.

The vulnerable technology relevant to our customer is: {matched_tech}

Source article title: {article_title}

Source article content (for context):
{content}

SAMPLE ADVISORY TEMPLATE:
{sample_text}

Output ONLY the complete markdown advisory document. Include YAML front matter matching the sample format (tlp, date, author, classification, template). Use today's date if needed. Replace all placeholder content with accurate, researched information specific to {cve_id} and {matched_tech}."""

    content_str, it, ot, cc, cr = call_llm(
        "You are an expert vulnerability researcher and technical writer producing client-ready security advisories.",
        [{"role": "user", "content": user_prompt}],
        temperature=0.3,
        max_tokens=4000,
        json_mode=False,
    )
    cost_tracker.add_tokens(it, ot, cc, cr)
    return _strip_code_fence(content_str)


def generate_threat_intelligence_markdown(
    article_title,
    article_content,
    article_url=None,
    customer_name=None,
    match_evidence=None,
    matched_tech=None,
    matched_affiliates=None,
    match_dimensions=None,
    distribution_outlook=None,
):
    """Call LLM to produce a TI advisory following the same Scriba sample structure."""
    if not has_api_key():
        raise RuntimeError(
            "LLM API key required to generate advisories "
            "(configure OpenAI, Anthropic, or OpenRouter in Settings)"
        )

    if not SAMPLE_ADVISORY.is_file():
        raise FileNotFoundError(f"Sample advisory not found: {SAMPLE_ADVISORY}")

    sample_text = SAMPLE_ADVISORY.read_text(encoding="utf-8")
    content = (article_content or "")[:12000]

    customer_line = customer_name or "our customer base"
    tech_line = ", ".join(matched_tech) if isinstance(matched_tech, list) else (matched_tech or "N/A")
    aff_line = (
        ", ".join(matched_affiliates)
        if isinstance(matched_affiliates, list)
        else (matched_affiliates or "N/A")
    )
    dims_line = (
        ", ".join(match_dimensions)
        if isinstance(match_dimensions, list)
        else (match_dimensions or "N/A")
    )

    user_prompt = f"""Take the sample advisory that is attached.

Now produce a client-ready threat intelligence security advisory about the threat described in the source article below. Follow the same markdown structure and YAML front matter as the sample (tlp, date, author, classification, template). Research with the most recent data — no shortcuts.

Adapt CVE-centric sections thoughtfully for a threat-intelligence advisory:
- Keep Executive Summary, Details, Impact, Affected Product/Environment, Recommendations, and References.
- If no single CVE applies, omit the CVE table or replace it with a threat/IOC summary table when relevant.
- Focus on adversary activity, tradecraft, affected environments, and defensive recommendations.

Customer relevance:
- Customer: {customer_line}
- Match dimensions: {dims_line}
- Matched technology: {tech_line}
- Matched affiliates: {aff_line}
- Why it matches: {match_evidence or "N/A"}
- Adversary movement outlook: {distribution_outlook or "N/A"}

Source article title: {article_title}
Source article URL: {article_url or "N/A"}

Source article content (for context):
{content}

SAMPLE ADVISORY TEMPLATE:
{sample_text}

Output ONLY the complete markdown advisory document. Use today's date. Title it for the threat/topic (not a placeholder). Include the source article URL in References."""

    content_str, it, ot, cc, cr = call_llm(
        "You are an expert threat intelligence analyst and technical writer producing client-ready security advisories.",
        [{"role": "user", "content": user_prompt}],
        temperature=0.3,
        max_tokens=4000,
        json_mode=False,
    )
    cost_tracker.add_tokens(it, ot, cc, cr)
    return _strip_code_fence(content_str)


def build_advisory_pdf(md_path, pdf_path):
    """Run Scriba PDF build for the generated markdown report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    md_rel = md_path.relative_to(SCRIBA_ROOT)
    pdf_rel = pdf_path.relative_to(SCRIBA_ROOT)

    cmd = [
        _python_executable(),
        "-m", "src.build",
        str(md_rel),
        "--template", "advisory",
        "--output", str(pdf_rel),
    ]
    logger.info("Running Scriba build: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(SCRIBA_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        logger.error("Scriba build stderr: %s", result.stderr)
        raise RuntimeError(f"Scriba PDF build failed: {result.stderr or result.stdout}")

    if not pdf_path.is_file():
        raise RuntimeError("Scriba build completed but PDF was not created")

    return pdf_path


def create_advisory(cve_id, technology, article_title, article_content):
    """Generate markdown advisory via LLM and build PDF with Scriba.

    Returns:
        dict with stem, markdown_path, pdf_path (absolute strings)
    """
    cve_id = cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID: {cve_id}")

    stem, md_path, pdf_path = advisory_paths(cve_id, technology)

    md_text = generate_advisory_markdown(cve_id, article_title, article_content, technology)
    md_path.write_text(md_text, encoding="utf-8")
    logger.info("Wrote advisory markdown: %s", md_path)

    build_advisory_pdf(md_path, pdf_path)

    return {
        "stem": stem,
        "markdown_path": str(md_path),
        "pdf_path": str(pdf_path),
        "pdf_filename": pdf_path.name,
    }


def create_threat_intelligence_advisory(
    article_id,
    article_title,
    article_content,
    article_url=None,
    customer_name=None,
    match_evidence=None,
    matched_tech=None,
    matched_affiliates=None,
    match_dimensions=None,
    distribution_outlook=None,
    topic=None,
):
    """Generate a TI advisory (no CVE required) and build PDF with Scriba."""
    topic_label = (topic or article_title or "threat-intelligence").strip()
    stem, md_path, pdf_path = ti_advisory_paths(article_id, topic_label, customer_name)

    md_text = generate_threat_intelligence_markdown(
        article_title=article_title,
        article_content=article_content,
        article_url=article_url,
        customer_name=customer_name,
        match_evidence=match_evidence,
        matched_tech=matched_tech,
        matched_affiliates=matched_affiliates,
        match_dimensions=match_dimensions,
        distribution_outlook=distribution_outlook,
    )
    md_path.write_text(md_text, encoding="utf-8")
    logger.info("Wrote TI advisory markdown: %s", md_path)

    build_advisory_pdf(md_path, pdf_path)

    return {
        "stem": stem,
        "markdown_path": str(md_path),
        "pdf_path": str(pdf_path),
        "pdf_filename": pdf_path.name,
    }
