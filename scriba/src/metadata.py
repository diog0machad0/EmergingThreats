from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any


class MetadataError(ValueError):
    """Raised when report metadata is missing or invalid."""


@dataclass(slots=True)
class ReportMetadata:
    tlp: str
    date: str
    author: str
    classification: str
    template: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReportMetadata":
        required = ("tlp", "date", "author", "classification", "template")
        missing = [key for key in required if not payload.get(key)]
        if missing:
            raise MetadataError(f"Missing required metadata fields: {', '.join(missing)}")

        tlp = str(payload["tlp"]).strip().upper()
        if tlp not in {"WHITE", "GREEN", "AMBER", "RED"}:
            raise MetadataError("tlp must be one of: WHITE, GREEN, AMBER, RED")

        date_value = str(payload["date"]).strip()
        try:
            date.fromisoformat(date_value)
        except ValueError as exc:
            raise MetadataError("date must be in ISO format YYYY-MM-DD") from exc

        return cls(
            tlp=tlp,
            date=date_value,
            author=str(payload["author"]).strip(),
            classification=str(payload["classification"]).strip(),
            template=str(payload["template"]).strip(),
        )