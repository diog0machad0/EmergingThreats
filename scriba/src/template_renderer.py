from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def build_jinja_env(templates_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml", "j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_template(templates_dir: Path, template_name: str, context: dict[str, Any]) -> str:
    env = build_jinja_env(templates_dir)
    template = env.get_template(template_name)
    return template.render(**context)