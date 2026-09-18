from __future__ import annotations

from pathlib import Path

from weasyprint import CSS, HTML

from .utils import ensure_parent_dir


def generate_pdf(html_content: str, output_path: Path, base_dir: Path, css_paths: list[Path]) -> None:
    ensure_parent_dir(output_path)
    stylesheets = [CSS(filename=str(path)) for path in css_paths]
    HTML(string=html_content, base_url=str(base_dir)).write_pdf(
        target=str(output_path),
        stylesheets=stylesheets,
    )