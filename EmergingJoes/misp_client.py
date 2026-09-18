"""MISP integration — push APT IOCs to threat-actor galaxy clusters."""

import logging
import re
from functools import lru_cache

from config import load_config

logger = logging.getLogger(__name__)

THREAT_ACTOR_GALAXY_TYPE = "threat-actor"


def misp_config():
    cfg = load_config()
    return {
        "url": (cfg.get("misp_url") or "https://127.0.0.1:8443").rstrip("/"),
        "api_key": cfg.get("misp_api_key") or "",
        "verify_ssl": bool(cfg.get("misp_verify_ssl", False)),
        "enabled": bool(cfg.get("misp_enabled", True)),
        "org_name": cfg.get("misp_org_name") or "Security Joes",
    }


def is_misp_configured():
    cfg = misp_config()
    return cfg["enabled"] and bool(cfg["api_key"])


def _get_client():
    from pymisp import PyMISP

    cfg = misp_config()
    if not cfg["api_key"]:
        raise RuntimeError("MISP API key not configured")
    return PyMISP(cfg["url"], cfg["api_key"], cfg["verify_ssl"])


def _normalize_match(value):
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


@lru_cache(maxsize=1)
def _threat_actor_galaxy_id():
    """Return MISP galaxy id for the threat-actor galaxy."""
    misp = _get_client()
    for g in misp.galaxies():
        galaxy = g.get("Galaxy") or g
        if galaxy.get("type") == THREAT_ACTOR_GALAXY_TYPE:
            return galaxy["id"]
    raise RuntimeError("Threat Actor galaxy not found in MISP")


def _cluster_entry(cluster):
    """Normalize a MISPGalaxyCluster or dict to our lookup entry."""
    if hasattr(cluster, "value"):
        value = cluster.value
        tag = cluster.tag_name
        meta = getattr(cluster, "meta", {}) or {}
    else:
        cluster = cluster.get("GalaxyCluster") or cluster
        value = cluster.get("value") or ""
        tag = cluster.get("tag_name") or f'misp-galaxy:threat-actor="{value}"'
        meta = cluster.get("meta") or {}
    return {
        "uuid": getattr(cluster, "uuid", None) or cluster.get("uuid"),
        "value": value,
        "tag_name": tag,
        "synonyms": meta.get("synonyms") or [],
    }


def find_threat_actor_cluster(display_name, aliases=None):
    """Find MISP galaxy cluster for an APT display name or alias."""
    if not is_misp_configured():
        return None
    try:
        misp = _get_client()
        galaxy_id = _threat_actor_galaxy_id()
        candidates = [display_name] + (aliases or [])

        for name in candidates:
            if not name:
                continue
            clusters = misp.search_galaxy_clusters(
                galaxy_id, searchall=name, pythonify=True,
            )
            if not clusters:
                continue
            want = _normalize_match(name)
            for cluster in clusters:
                entry = _cluster_entry(cluster)
                keys = {_normalize_match(entry["value"])}
                keys.update(_normalize_match(s) for s in entry["synonyms"])
                if want in keys or want in _normalize_match(entry["value"]):
                    return entry

        m = re.search(r"apt\s*[-_]?\s*(\d+)", (display_name or "").lower())
        if m:
            clusters = misp.search_galaxy_clusters(
                galaxy_id, searchall=f"APT{m.group(1)}", pythonify=True,
            )
            if clusters:
                return _cluster_entry(clusters[0])
        return None
    except Exception as e:
        logger.warning("MISP galaxy lookup failed: %s", e)
        return None


def test_connection():
    """Return (ok, message) for MISP connectivity."""
    if not misp_config()["enabled"]:
        return False, "MISP integration disabled"
    if not misp_config()["api_key"]:
        return False, "MISP API key not set (Settings)"
    try:
        misp = _get_client()
        resp = misp.misp_instance_version
        version = resp.get("version") if isinstance(resp, dict) else str(resp)
        return True, f"Connected — MISP {version}"
    except Exception as e:
        return False, str(e)


def create_apt_ioc_event(
    apt_display_name,
    apt_aliases,
    article_title,
    article_url,
    iocs,
    campaign=None,
    context=None,
    source_name=None,
):
    """Create a MISP event with IOC attributes linked to threat-actor galaxy.

    Returns dict with event_id, event_uuid, galaxy_tag, ioc_count.
    """
    from pymisp import MISPEvent, MISPAttribute, MISPObject

    if not iocs:
        raise ValueError("No IOCs to export")

    cluster = find_threat_actor_cluster(apt_display_name, apt_aliases)
    galaxy_tag = cluster["tag_name"] if cluster else None

    info = f"[JOES] {apt_display_name}: {article_title[:120]}"
    comment_parts = [
        f"Source article: {article_title}",
        f"URL: {article_url}",
    ]
    if source_name:
        comment_parts.append(f"Feed: {source_name}")
    if campaign:
        comment_parts.append(f"Campaign: {campaign}")
    if context:
        comment_parts.append(f"Context: {context}")
    default_comment = " | ".join(comment_parts)

    event = MISPEvent()
    event.info = info
    event.distribution = 0  # org only
    event.threat_level_id = 2  # medium
    event.analysis = 1  # ongoing

    if galaxy_tag:
        event.add_tag(galaxy_tag)
    event.add_tag(f"apt:{apt_display_name.lower().replace(' ', '-')}")
    event.add_tag("source:joes-ti")

    for ioc in iocs:
        attr = MISPAttribute()
        attr.type = ioc["type"]
        attr.value = ioc["value"]
        attr.comment = ioc.get("comment") or default_comment
        attr.to_ids = True
        event.add_attribute(**attr)

    try:
        obj = MISPObject("external-link")
        obj.add_attribute("link", value=article_url, comment=article_title)
        event.add_object(obj)
    except Exception:
        pass

    misp = _get_client()
    result = misp.add_event(event, pythonify=True)
    if hasattr(result, "id"):
        return {
            "event_id": result.id,
            "event_uuid": result.uuid,
            "galaxy_tag": galaxy_tag,
            "galaxy_cluster": cluster["value"] if cluster else None,
            "ioc_count": len(iocs),
        }
    if isinstance(result, dict) and result.get("Event"):
        ev = result["Event"]
        return {
            "event_id": ev.get("id"),
            "event_uuid": ev.get("uuid"),
            "galaxy_tag": galaxy_tag,
            "galaxy_cluster": cluster["value"] if cluster else None,
            "ioc_count": len(iocs),
        }
    raise RuntimeError(f"Unexpected MISP response: {result}")
