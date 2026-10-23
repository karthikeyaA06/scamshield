"""Deterministic rule scoring: evidence -> score (0-100) -> verdict floor.

The weights live in assets/rules.json and are explained in references/RULES.md.
The model can raise this verdict but never lower it (see explain.py).

Usage:
    python score.py evidence.json      # output of analyze_apk.py / analyze_qr.py
"""

from __future__ import annotations

import json
import sys

try:
    from .common import load_asset
except ImportError:  # pragma: no cover
    from common import load_asset

VERDICTS = ["Safe", "Suspicious", "Dangerous"]

SMS_PERMS = {"perm.READ_SMS", "perm.RECEIVE_SMS"}
EXFIL_KEYS = {"string.telegram_bot", "string.raw_ip"}
TAKEOVER_KEYS = {"perm.BIND_ACCESSIBILITY_SERVICE"}
TAKEOVER_PARTNERS = {"perm.READ_SMS", "perm.RECEIVE_SMS", "perm.SYSTEM_ALERT_WINDOW",
                     "perm.BIND_NOTIFICATION_LISTENER_SERVICE"}


def verdict_for(score: int) -> str:
    t = load_asset("rules.json")["thresholds"]
    if score >= t["dangerous"]:
        return "Dangerous"
    if score >= t["suspicious"]:
        return "Suspicious"
    return "Safe"


def more_severe(a: str, b: str) -> str:
    return a if VERDICTS.index(a) >= VERDICTS.index(b) else b


def score(analysis: dict) -> dict:
    cfg = load_asset("rules.json")
    weights = cfg["rules"]
    evidence = analysis["evidence"]

    by_key: dict[str, list[str]] = {}
    for item in evidence:
        if item["key"] in weights:
            by_key.setdefault(item["key"], []).append(item["id"])

    hits: list[dict] = []
    perm_total = 0
    for key, ids in by_key.items():
        w = weights[key]
        if key.startswith("perm."):
            allowed = max(0, min(w, cfg["permission_cap"] - perm_total))
            perm_total += allowed
            w = allowed
        hits.append({"rule": key, "weight": w, "evidence_ids": ids, "combo": False})

    def ids_for(keys: set[str]) -> list[str]:
        return sorted({i for k in keys if k in by_key for i in by_key[k]}, key=lambda i: int(i[1:]))

    present = set(by_key)
    if present & SMS_PERMS and present & EXFIL_KEYS:
        hits.append({"rule": "combo.otp_theft", "weight": weights["combo.otp_theft"],
                     "evidence_ids": ids_for(SMS_PERMS | EXFIL_KEYS), "combo": True})
    if present & TAKEOVER_KEYS and present & TAKEOVER_PARTNERS:
        hits.append({"rule": "combo.screen_takeover", "weight": weights["combo.screen_takeover"],
                     "evidence_ids": ids_for(TAKEOVER_KEYS | TAKEOVER_PARTNERS), "combo": True})
    if "impersonation" in present and present & (SMS_PERMS | {"perm.SEND_SMS"}):
        hits.append({"rule": "combo.fake_official_sms", "weight": weights["combo.fake_official_sms"],
                     "evidence_ids": ids_for({"impersonation"} | SMS_PERMS | {"perm.SEND_SMS"}),
                     "combo": True})
    if {"qr.prefilled_amount", "qr.receive_wording"} <= present:
        hits.append({"rule": "combo.fake_receive", "weight": weights["combo.fake_receive"],
                     "evidence_ids": ids_for({"qr.prefilled_amount", "qr.receive_wording"}),
                     "combo": True})

    raw = sum(h["weight"] for h in hits)
    total = min(100, raw)
    hits.sort(key=lambda h: (-h["weight"], h["rule"]))
    return {
        "score": total,
        "raw_score": raw,
        "floor": verdict_for(total),
        "thresholds": cfg["thresholds"],
        "hits": [h for h in hits if h["weight"] > 0],
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    with open(sys.argv[1], encoding="utf-8") as fh:
        print(json.dumps(score(json.load(fh)), indent=2))
