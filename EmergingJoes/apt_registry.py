"""Canonical threat-actor (APT) resolution and alias grouping."""

import re

from mitre_data import KNOWN_THREAT_ACTORS, _THREAT_ACTOR_DATA, _normalize

# canonical_tag -> {display_name, aliases[], all_tags[]}
_CANONICAL = {}
# any normalized tag/alias -> canonical_tag
_TAG_TO_CANONICAL = {}


def _build_registry():
    if _CANONICAL:
        return
    for primary, aliases in _THREAT_ACTOR_DATA:
        canonical_tag = _normalize(primary)
        alias_tags = [_normalize(a) for a in aliases if a]
        all_tags = list(dict.fromkeys([canonical_tag] + alias_tags))
        entry = {
            "canonical_tag": canonical_tag,
            "display_name": primary,
            "aliases": aliases,
            "all_tags": all_tags,
        }
        _CANONICAL[canonical_tag] = entry
        for tag in all_tags:
            _TAG_TO_CANONICAL[tag] = canonical_tag


def resolve_threat_actor(tag_or_name):
    """Resolve a tag or display name to canonical APT metadata.

    Returns dict with canonical_tag, display_name, aliases, matched_as
    or None if not a known threat actor.
    """
    _build_registry()
    if not tag_or_name:
        return None
    key = _normalize(str(tag_or_name).strip())
    if not key:
        return None

    canonical = _TAG_TO_CANONICAL.get(key)
    if not canonical and key in KNOWN_THREAT_ACTORS:
        # KNOWN lookup maps alias -> display primary name
        primary_display = KNOWN_THREAT_ACTORS[key]
        canonical = _TAG_TO_CANONICAL.get(_normalize(primary_display))
    if not canonical:
        # apt29 vs apt-29 style
        m = re.match(r"^apt[-_]?(\d+)$", key.replace("_", "-"))
        if m:
            canonical = _TAG_TO_CANONICAL.get(f"apt{m.group(1)}")
    if not canonical:
        return None

    entry = dict(_CANONICAL[canonical])
    entry["matched_as"] = key
    return entry


def tags_to_canonical_actors(tags):
    """Return unique canonical APT entries referenced by summary tags."""
    _build_registry()
    seen = {}
    for tag in tags or []:
        resolved = resolve_threat_actor(tag)
        if resolved:
            seen[resolved["canonical_tag"]] = resolved
    return list(seen.values())


def is_threat_actor_tag(tag):
    return resolve_threat_actor(tag) is not None


def all_canonical_actors():
    """All known MITRE threat actors with metadata."""
    _build_registry()
    return sorted(_CANONICAL.values(), key=lambda x: x["display_name"].lower())
