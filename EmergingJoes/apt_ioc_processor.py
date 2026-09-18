"""Process APT-tagged articles: extract IOCs and push to MISP."""

import json
import logging

from apt_registry import resolve_threat_actor, tags_to_canonical_actors
from database import get_apt_ioc_export, save_apt_ioc_export
from ioc_extractor import extract_article_iocs, to_misp_attributes
from misp_client import create_apt_ioc_event, is_misp_configured

logger = logging.getLogger(__name__)


def _parse_tags(tags_field):
    if not tags_field:
        return []
    if isinstance(tags_field, list):
        return tags_field
    try:
        return json.loads(tags_field)
    except (json.JSONDecodeError, TypeError):
        return []


def process_apt_iocs_for_article(article_id, title, content, tags, summary_text=None, article_url="", source_name=None):
    """Extract IOCs for APT-attributed articles and export to MISP.

    Skips if already exported or no APT+IOC combination found.
    Returns export record dict or None.
    """
    if get_apt_ioc_export(article_id):
        logger.debug("Article %s already exported to MISP", article_id)
        return None

    if not article_url or not source_name:
        from database import get_article
        full = get_article(article_id)
        if full:
            article_url = article_url or full.get("url") or ""
            source_name = source_name or full.get("source_name")

    tags_list = _parse_tags(tags)
    actors = tags_to_canonical_actors(tags_list)
    if not actors:
        # Also scan title/content for known APT names
        blob = f"{title}\n{content or ''}"
        from apt_registry import all_canonical_actors
        for entry in all_canonical_actors():
            for tag in entry["all_tags"]:
                if tag.replace("-", " ") in blob.lower() or tag in blob.lower():
                    actors.append(entry)
                    break
            if len(actors) >= 3:
                break
        # dedupe
        seen = set()
        unique = []
        for a in actors:
            if a["canonical_tag"] not in seen:
                seen.add(a["canonical_tag"])
                unique.append(a)
        actors = unique

    if not actors:
        return None

    apt_names = [a["display_name"] for a in actors]
    extraction = extract_article_iocs(title, content, summary_text, apt_names)
    iocs = extraction.get("iocs") or []
    if not iocs:
        logger.info("  APT IOCs: no IOCs found for article %s (%s)", article_id, ", ".join(apt_names))
        return None

    primary = actors[0]
    misp_attrs = to_misp_attributes(
        iocs,
        default_comment=f"JOES Threat Intelligence — {title}",
    )

    export_data = {
        "article_id": article_id,
        "canonical_apt": primary["canonical_tag"],
        "apt_display_name": primary["display_name"],
        "apt_aliases_json": json.dumps(primary.get("aliases") or []),
        "ioc_count": len(misp_attrs),
        "iocs_json": json.dumps(iocs),
        "campaign": extraction.get("campaign"),
        "context": extraction.get("context"),
        "misp_event_id": None,
        "misp_event_uuid": None,
        "misp_galaxy_tag": None,
        "status": "pending",
        "error_message": None,
    }

    if not is_misp_configured():
        export_data["status"] = "skipped"
        export_data["error_message"] = "MISP not configured"
        save_apt_ioc_export(**export_data)
        logger.info("  APT IOCs: %d IOC(s) found but MISP not configured (article %s)", len(iocs), article_id)
        return export_data

    try:
        result = create_apt_ioc_event(
            apt_display_name=primary["display_name"],
            apt_aliases=primary.get("aliases") or [],
            article_title=title,
            article_url=article_url or "",
            iocs=misp_attrs,
            campaign=extraction.get("campaign"),
            context=extraction.get("context"),
            source_name=source_name,
        )
        export_data["status"] = "exported"
        export_data["misp_event_id"] = result.get("event_id")
        export_data["misp_event_uuid"] = result.get("event_uuid")
        export_data["misp_galaxy_tag"] = result.get("galaxy_tag")
        save_apt_ioc_export(**export_data)
        logger.info(
            "  APT IOCs: exported %d IOC(s) for %s to MISP event %s",
            len(misp_attrs), primary["display_name"], result.get("event_id"),
        )
        return export_data
    except Exception as e:
        export_data["status"] = "failed"
        export_data["error_message"] = str(e)
        save_apt_ioc_export(**export_data)
        logger.warning("  APT IOC export failed for article %s: %s", article_id, e)
        return export_data
