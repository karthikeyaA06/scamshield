"""Pluggable UPI ID -> registered name lookup.

DEMO IMPLEMENTATION (MOCK DATA): reads assets/demo_merchants.json, a list of
invented shops. It does not contact any bank or NPCI.

Why a mock: the real registered name behind a UPI ID is only available through
NPCI member banks and licensed payment apps, or through a licensed UPI ID
verification provider (paid, business KYC, needs internet). In production,
replace `verify_upi_id` with a call to such a provider. Everything else in
ScamShield stays offline.

Usage:
    python verify_upi.py someone@okaxis
"""

from __future__ import annotations

import json
import sys

try:
    from .common import load_asset
except ImportError:  # pragma: no cover
    from common import load_asset

IS_MOCK = True


def verify_upi_id(upi_id: str) -> dict | None:
    """Return {"upi_id", "registered_name", "source"} or None if unknown."""
    data = load_asset("demo_merchants.json")
    name = data["merchants"].get(upi_id.strip().lower())
    if name is None:
        return None
    return {"upi_id": upi_id, "registered_name": name, "source": "MOCK DATA (demo_merchants.json)"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    print("MOCK DATA: demo lookup only, not a real bank check.", file=sys.stderr)
    print(json.dumps(verify_upi_id(sys.argv[1]), indent=2))
