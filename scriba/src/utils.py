from __future__ import annotations

import re
from pathlib import Path


def ensure_parent_dir(path: Path) -> None:
    """Create parent directory for a file path if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)


def slugify(value: str) -> str:
    """Create stable HTML ids from headings."""
    normalized = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9\s-]", "", normalized)
    normalized = re.sub(r"[\s-]+", "-", normalized).strip("-")
    return normalized or "section"