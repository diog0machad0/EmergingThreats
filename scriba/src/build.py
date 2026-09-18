from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from .markdown_loader import load_markdown
from .pdf_generator import generate_pdf
from .template_renderer import render_template
from .toc import enrich_html_with_toc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate cybersecurity advisory PDFs from markdown.")
    parser.add_argument("report", type=Path, help="Path to markdown advisory report.")
    parser.add_argument("--template", default=None, help="Template name override (e.g. advisory).")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/report.pdf"),
        help="Destination PDF path.",
    )
    return parser.parse_args()


def _format_long_date(iso_date: str) -> str:
    parsed = date.fromisoformat(iso_date)
    return parsed.strftime("%B %d, %Y").replace(" 0", " ")


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    templates_dir = project_root / "templates"
    styles_dir = project_root / "styles"

    report = load_markdown(args.report)
    body_html, _toc_items = enrich_html_with_toc(report.body_html)

    template_base_name = args.template or report.metadata.template
    template_file = f"{template_base_name}.html.j2"

    html = render_template(
        templates_dir=templates_dir,
        template_name=template_file,
        context={
            "metadata": report.metadata,
            "title": report.title,
            "title_main": report.title_main,
            "title_identifier": report.title_identifier,
            "subtitle": report.subtitle,
            "body_html": body_html,
            "display_date": _format_long_date(report.metadata.date),
        },
    )

    css_paths = [styles_dir / "main.css", styles_dir / "cover.css", styles_dir / "print.css"]
    generate_pdf(
        html_content=html,
        output_path=args.output,
        base_dir=project_root,
        css_paths=css_paths,
    )
    print(f"PDF generated at {args.output}")


if __name__ == "__main__":
    main()
