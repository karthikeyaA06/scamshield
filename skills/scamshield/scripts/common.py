"""Shared helpers for ScamShield scripts: asset loading and evidence building."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
ASSETS = SKILL_ROOT / "assets"

MAX_APK_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB

DISCLAIMER = {
    "en": "ScamShield gives guidance, not a guarantee. Do not install or pay if unsure. "
          "Call 1930 or report at cybercrime.gov.in.",
    "kn": "ScamShield ಮಾರ್ಗದರ್ಶನ ನೀಡುತ್ತದೆ, ಖಾತರಿ ಅಲ್ಲ. ಸಂದೇಹವಿದ್ದರೆ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಪಾವತಿಸಬೇಡಿ. "
          "1930 ಗೆ ಕರೆ ಮಾಡಿ ಅಥವಾ cybercrime.gov.in ನಲ್ಲಿ ದೂರು ನೀಡಿ.",
}


@lru_cache(maxsize=None)
def load_asset(name: str) -> dict:
    with open(ASSETS / name, encoding="utf-8") as fh:
        return json.load(fh)


class EvidenceBuilder:
    """Collects evidence items and gives each a stable ID (E1, E2, ...)."""

    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, type_: str, key: str, value: str, severity: str = "info",
            label: str = "", params: dict | None = None) -> str:
        eid = f"E{len(self.items) + 1}"
        self.items.append({
            "id": eid,
            "type": type_,
            "key": key,          # rule key used by score.py, or "info.*"
            "value": value,      # the raw extracted value
            "label": label,      # short plain-English description for the UI
            "severity": severity,
            "params": params or {},
        })
        return eid


def severity_for(weight: int) -> str:
    if weight >= 20:
        return "high"
    if weight >= 10:
        return "medium"
    if weight > 0:
        return "low"
    return "info"


class InputError(ValueError):
    """Raised for input the user should fix (wrong file type, too large, unreadable)."""
