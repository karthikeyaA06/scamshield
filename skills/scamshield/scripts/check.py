"""One-step check: analyze -> score -> explain. This is the script an agent should run.

Usage:
    python check.py --apk path/to/app.apk
    python check.py --qr path/to/qr.png --shop "Sharma General Store"
    python check.py --qr "upi://pay?pa=...&pn=..."
Add --no-model to skip Gemma and use rule explanations only.
Add --lang kn to print the summary in Kannada.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .analyze_apk import analyze_apk
    from .analyze_qr import analyze_qr, analyze_qr_image
    from .common import InputError
    from .explain import explain
except ImportError:  # pragma: no cover
    from analyze_apk import analyze_apk
    from analyze_qr import analyze_qr, analyze_qr_image
    from common import InputError
    from explain import explain


def run(apk: str | None = None, qr: str | None = None, shop: str | None = None,
        use_model: bool = True) -> dict:
    if apk:
        analysis = analyze_apk(apk)
    elif qr:
        p = Path(qr)
        analysis = analyze_qr_image(p.read_bytes(), shop) if p.exists() else analyze_qr(qr, shop)
    else:
        raise InputError("Give --apk or --qr.")
    return explain(analysis, use_model=use_model)


def main() -> int:
    ap = argparse.ArgumentParser(description="ScamShield: check an APK or UPI QR code offline.")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--apk", help="Path to an Android APK file")
    group.add_argument("--qr", help="Path to a QR image, or a upi:// link")
    ap.add_argument("--shop", help="Shop name you expect to pay (QR only)")
    ap.add_argument("--no-model", action="store_true", help="Rule explanations only")
    ap.add_argument("--lang", choices=["en", "kn"], default=None,
                    help="Print a short human summary in this language instead of JSON")
    args = ap.parse_args()
    try:
        result = run(args.apk, args.qr, args.shop, use_model=not args.no_model)
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        return 1
    if args.lang:
        lang = args.lang
        print(f"Verdict: {result['verdict']}  (rule score {result['score']}/100)")
        print(result[f"summary_{lang}"])
        for r in result["reasons"]:
            print(f"- {r[lang]}  [{', '.join(r['evidence_ids'])}]")
        print("Next steps:")
        for s in result[f"next_steps_{lang}"]:
            print(f"- {s}")
        print(f"(model: {result['ai']['model']}, status: {result['ai']['status']})")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
