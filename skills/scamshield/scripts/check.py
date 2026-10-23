"""One-step check: analyze -> score -> explain. This is the script an agent should run.

Usage:
    python check.py --apk path/to/app.apk        (also works for .exe programs)
    python check.py --file path/to/anything      (APK or EXE, detected from the file itself)
    python check.py --qr path/to/qr.png --shop "Sharma General Store"
    python check.py --qr "upi://pay?pa=...&pn=..."
    python check.py --sms "Your account will be blocked..." --sender "+919812345678"
Add --no-model to skip Gemma and use rule explanations only.
Add --lang kn to print the summary in Kannada.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .analyze_file import analyze_file
    from .analyze_qr import analyze_qr, analyze_qr_image
    from .analyze_sms import analyze_sms
    from .common import InputError
    from .explain import explain
except ImportError:  # pragma: no cover
    from analyze_file import analyze_file
    from analyze_qr import analyze_qr, analyze_qr_image
    from analyze_sms import analyze_sms
    from common import InputError
    from explain import explain


def run(apk: str | None = None, qr: str | None = None, shop: str | None = None,
        use_model: bool = True, sms: str | None = None, sender: str | None = None) -> dict:
    if sms:
        analysis = analyze_sms(sms, sender)
    elif apk:
        analysis = analyze_file(apk)
    elif qr:
        p = Path(qr)
        analysis = analyze_qr_image(p.read_bytes(), shop) if p.exists() else analyze_qr(qr, shop)
    else:
        raise InputError("Give --apk, --qr or --sms.")
    return explain(analysis, use_model=use_model)


def main() -> int:
    ap = argparse.ArgumentParser(description="ScamShield: check an APK, EXE, UPI QR code or message offline.")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--apk", "--file", dest="apk", help="Path to an APK or EXE file")
    group.add_argument("--qr", help="Path to a QR image, or a upi:// link")
    group.add_argument("--sms", help="Text of a suspicious SMS or WhatsApp message")
    ap.add_argument("--shop", help="Shop name you expect to pay (QR only)")
    ap.add_argument("--sender", help="Sender ID or number of the message (SMS only)")
    ap.add_argument("--no-model", action="store_true", help="Rule explanations only")
    ap.add_argument("--lang", choices=["en", "kn"], default=None,
                    help="Print a short human summary in this language instead of JSON")
    args = ap.parse_args()
    try:
        result = run(args.apk, args.qr, args.shop, use_model=not args.no_model,
                     sms=args.sms, sender=args.sender)
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
