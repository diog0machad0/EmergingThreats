from __future__ import annotations

from dataclasses import dataclass

from bs4 import BeautifulSoup

from .utils import slugify


@dataclass(slots=True)
class TocItem:
    level: int
    title: str
    anchor: str


def enrich_html_with_toc(html: str) -> tuple[str, list[TocItem]]:
    """Assign heading ids and return TOC items."""
    soup = BeautifulSoup(html, "html.parser")
    toc: list[TocItem] = []
    used_anchors: dict[str, int] = {}

    for heading in soup.select("h1, h2, h3"):
        title = heading.get_text(" ", strip=True)
        if not title:
            continue
        base_anchor = slugify(title)
        duplicate_count = used_anchors.get(base_anchor, 0)
        used_anchors[base_anchor] = duplicate_count + 1
        anchor = base_anchor if duplicate_count == 0 else f"{base_anchor}-{duplicate_count + 1}"
        heading["id"] = anchor
        toc.append(TocItem(level=int(heading.name[1]), title=title, anchor=anchor))

    return str(soup), toc