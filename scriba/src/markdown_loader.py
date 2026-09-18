from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from markdown_it import MarkdownIt
from mdit_py_plugins.footnote import footnote_plugin

from .metadata import ReportMetadata


FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
H1_PATTERN = re.compile(r"(?m)^#\s+(.+?)\s*$")
H2_PATTERN = re.compile(r"(?m)^##\s+(.+?)\s*$")
TITLE_TRAILING_PARENS_PATTERN = re.compile(r"^(?P<main>.+?)\s+(?P<identifier>\([^()]+\))\s*$")


@dataclass(slots=True)
class LoadedReport:
    metadata: ReportMetadata
    title: str
    title_main: str
    title_identifier: str | None
    subtitle: str | None
    body_html: str


def _custom_fence_renderer(
    _renderer: Any,
    tokens: list[Any],
    idx: int,
    options: dict[str, Any],
    env: dict[str, Any],
) -> str:
    token = tokens[idx]
    info = (token.info or "").strip().lower()
    content = token.content.rstrip()

    if info == "ioc":
        escaped = (
            content.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        return f'<pre class="ioc-block"><code>{escaped}</code></pre>\n'

    lang_class = f' class="language-{info}"' if info else ""
    escaped = (
        content.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    return f"<pre><code{lang_class}>{escaped}</code></pre>\n"


def _extract_frontmatter(markdown_text: str) -> tuple[dict[str, Any], str]:
    match = FRONTMATTER_PATTERN.match(markdown_text)
    if not match:
        raise ValueError("Markdown report must include YAML frontmatter.")

    metadata = yaml.safe_load(match.group(1)) or {}
    content = markdown_text[match.end() :].lstrip()
    if not isinstance(metadata, dict):
        raise ValueError("YAML frontmatter must deserialize to a dictionary.")
    return metadata, content


def _extract_title_and_subtitle(content: str) -> tuple[str, str | None, str]:
    h1_match = H1_PATTERN.search(content)
    if not h1_match:
        raise ValueError("Report body must contain a first H1 heading for the title.")

    title = h1_match.group(1).strip()
    body = content[: h1_match.start()] + content[h1_match.end() :]
    body = body.lstrip()

    subtitle: str | None = None
    h2_match = H2_PATTERN.search(body)
    if h2_match:
        subtitle = h2_match.group(1).strip()
        body = body[: h2_match.start()] + body[h2_match.end() :]
        body = body.lstrip()

    return title, subtitle, body


def _build_markdown_engine() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": True})
    md.enable(["table", "strikethrough"])
    md.use(footnote_plugin)
    md.options["highlight"] = None
    md.add_render_rule("fence", _custom_fence_renderer)
    return md


def load_markdown(report_path: Path) -> LoadedReport:
    markdown_text = report_path.read_text(encoding="utf-8")
    raw_metadata, content = _extract_frontmatter(markdown_text)
    title, subtitle, body_markdown = _extract_title_and_subtitle(content)
    metadata = ReportMetadata.from_dict(raw_metadata)
    body_html = _build_markdown_engine().render(body_markdown)
    title_main = title
    title_identifier: str | None = None
    trailing_match = TITLE_TRAILING_PARENS_PATTERN.match(title)
    if trailing_match:
        title_main = trailing_match.group("main").strip()
        title_identifier = trailing_match.group("identifier").strip()
    return LoadedReport(
        metadata=metadata,
        title=title,
        title_main=title_main,
        title_identifier=title_identifier,
        subtitle=subtitle,
        body_html=body_html,
    )