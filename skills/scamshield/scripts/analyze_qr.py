"""Decode a QR code and inspect its UPI payment link -> evidence JSON.

Usage:
    python analyze_qr.py path/to/qr.png [--shop "Shop name"]
    python analyze_qr.py "upi://pay?pa=...&pn=..." [--shop "Shop name"]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from .common import EvidenceBuilder, InputError, MAX_IMAGE_BYTES, load_asset, severity_for
    from .verify_upi import IS_MOCK, verify_upi_id
except ImportError:  # pragma: no cover
    from common import EvidenceBuilder, InputError, MAX_IMAGE_BYTES, load_asset, severity_for
    from verify_upi import IS_MOCK, verify_upi_id

RECEIVE_WORDS = ["receive", "refund", "cashback", "cash back", "prize", "reward", "won",
                 "winner", "lottery", "bonus", "claim", "get money", "credited",
                 "kyc", "gift", "scholarship amount"]
PERSONAL_HANDLE_RE = re.compile(r"^(\+?91)?\d{10}@", re.I)
NAME_MATCH_MIN = 70       # rapidfuzz score below this = shop name mismatch
REGISTRY_MATCH_MIN = 70   # registered name vs QR name


def _pick(texts: list[str]) -> str | None:
    """If an image has several codes, prefer the payment one."""
    texts = [t for t in texts if t]
    for t in texts:
        if t.lower().startswith("upi:") or t.startswith("000201"):
            return t
    return texts[0] if texts else None


def _decode_zxing(img) -> str | None:
    """zxing-cpp copes with real phone photos: angles, glare, blur, logos, dense codes."""
    try:
        import zxingcpp
    except ImportError:
        return None
    try:
        results = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)
    except Exception:
        return None
    return _pick([r.text for r in results])


def _decode_opencv(img) -> str | None:
    """Fallback: OpenCV detectors over a few resized and contrast-boosted versions."""
    import cv2

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    variants = []
    h, w = gray.shape[:2]
    for side in (None, 1600, 1000):
        if side is None:
            variants.append(gray)
        elif max(h, w) > side:
            f = side / max(h, w)
            variants.append(cv2.resize(gray, (int(w * f), int(h * f)), interpolation=cv2.INTER_AREA))
    if max(h, w) < 600:
        variants.append(cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_NEAREST))
    boosted = [cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(v) for v in variants]
    otsu = [cv2.threshold(v, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1] for v in variants]

    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.insert(0, cv2.QRCodeDetectorAruco())
    for candidate in variants + boosted + otsu:
        for det in detectors:
            try:
                text, _, _ = det.detectAndDecode(candidate)
            except Exception:
                continue
            if text:
                return text
    return None


def decode_qr_image(data: bytes) -> str:
    """Decode the QR code in an image. Raises InputError if none is found."""
    if len(data) > MAX_IMAGE_BYTES:
        raise InputError("The image is larger than 10 MB.")
    import cv2
    import numpy as np

    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise InputError("This file is not an image ScamShield can read. Use a PNG or JPG "
                         "(on iPhone, take a screenshot of the photo).")
    text = _decode_zxing(img) or _decode_opencv(img)
    if text:
        return text
    raise InputError("No QR code was found in this image. Hold the phone straight, fill most "
                     "of the frame with the QR, and avoid glare. Or paste the UPI link instead.")


def parse_emv(payload: str) -> dict:
    """Parse an EMVCo / Bharat QR string (starts with "000201") into its main fields.

    Returns {"upi", "name", "amount", "city"} with any UPI ID found inside the
    merchant account templates (tags 26-51)."""
    def tlv(s: str) -> dict:
        out, i = {}, 0
        while i + 4 <= len(s):
            tag, length = s[i:i + 2], s[i + 2:i + 4]
            if not length.isdigit():
                break
            n = int(length)
            out[tag] = s[i + 4:i + 4 + n]
            i += 4 + n
        return out

    top = tlv(payload)
    upi = None
    for tag in range(26, 52):
        value = top.get(f"{tag:02d}")
        if not value:
            continue
        for sub in tlv(value).values():
            if "@" in sub and " " not in sub and len(sub) < 100:
                upi = sub
                break
        if upi:
            break
    return {"upi": upi, "name": top.get("59", ""), "amount": top.get("54", ""), "city": top.get("60", "")}


def _matches(text: str, words: list[str]) -> list[str]:
    low = text.lower()
    return [w for w in words if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low)]


GENERIC_NAME_WORDS = {"store", "stores", "general", "shop", "shoppe", "mart", "supermarket",
                      "cafe", "café", "bakery", "hotel", "restaurant", "kirana", "traders",
                      "enterprises", "agency", "agencies", "sri", "shri", "shree", "the", "and",
                      "&", "co", "pvt", "ltd", "medicals", "medical", "pharmacy"}


def _distinctive(name: str) -> str:
    words = re.findall(r"[\w&]+", name.lower())
    kept = [w for w in words if w not in GENERIC_NAME_WORDS]
    return " ".join(kept) or " ".join(words)


def _similarity(a: str, b: str) -> float:
    """Compare the distinctive part of two names ("Sharma General Store" -> "sharma")."""
    from rapidfuzz import fuzz
    return fuzz.token_set_ratio(_distinctive(a), _distinctive(b))


def analyze_qr(payload: str, shop_name: str | None = None) -> dict:
    payload = (payload or "").strip()
    if not payload:
        raise InputError("The QR code is empty.")
    rules = load_asset("rules.json")["rules"]
    ev = EvidenceBuilder()
    shop_name = (shop_name or "").strip() or None
    meta: dict = {"raw": payload[:500], "shop_name": shop_name}

    if payload.startswith("000201"):  # Bharat QR / EMVCo merchant QR
        emv = parse_emv(payload)
        meta["format"] = "Bharat QR"
        if not emv["upi"]:
            meta["type"] = "text"
            ev.add("qr", "info.bharat_qr", emv["name"] or "Bharat QR",
                   label="Bharat QR for card payments, with no UPI ID inside")
            return {"kind": "qr", "meta": meta, "evidence": ev.items}
        query = {"pa": emv["upi"], "pn": emv["name"]}
        if emv["amount"]:
            query["am"] = emv["amount"]
        from urllib.parse import urlencode
        payload = "upi://pay?" + urlencode(query)

    parsed = urlparse(payload)
    scheme = parsed.scheme.lower()

    if scheme in ("http", "https"):
        host = parsed.hostname or payload
        meta["type"] = "web_link"
        ev.add("qr", "qr.web_link", payload[:200], severity_for(rules["qr.web_link"]),
               label="Opens a website instead of a payment", params={"host": host})
        return {"kind": "qr", "meta": meta, "evidence": ev.items}

    if scheme != "upi":
        meta["type"] = "text"
        ev.add("qr", "info.text", payload[:200], label="Plain text, not a payment")
        return {"kind": "qr", "meta": meta, "evidence": ev.items}

    meta["type"] = "upi"
    params = {k.lower(): v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    pa = params.get("pa", "").strip()
    pn = params.get("pn", "").strip()
    am = params.get("am", "").strip()
    tn = params.get("tn", "").strip()
    meta.update(payee_upi=pa, payee_name=pn, amount=am, note=tn, merchant_code=params.get("mc", ""))

    if not pa:
        raise InputError("This UPI link has no payee UPI ID (pa), so it is not a valid payment QR.")

    ev.add("qr", "info.payee_upi", pa, label="Money goes to this UPI ID")
    if pn:
        ev.add("qr", "info.payee_name", pn, label="Name written inside the QR (anyone can type this)")

    if am:
        try:
            amount_val = float(am)
        except ValueError:
            amount_val = 0.0
        if amount_val > 0:
            shown = f"{amount_val:,.0f}" if amount_val.is_integer() else f"{amount_val:,.2f}"
            ev.add("qr", "qr.prefilled_amount", f"₹{shown}",
                   severity_for(rules["qr.prefilled_amount"]),
                   label="Amount is already filled in", params={"amount": shown})

    receive_hits = _matches(f"{tn} {pn}", RECEIVE_WORDS)
    if tn:
        ev.add("qr", "info.note", tn, label="Payment note inside the QR")
    if receive_hits:
        ev.add("qr", "qr.receive_wording", ", ".join(receive_hits),
               severity_for(rules["qr.receive_wording"]),
               label="Promises you will receive money",
               params={"words": tn or pn})

    # Many genuine small shops and individuals in India use mobile-number UPI IDs, so this
    # only counts as risk when the QR also promises money (the "refund"/"cashback" trick).
    if PERSONAL_HANDLE_RE.match(pa) and receive_hits:
        ev.add("qr", "qr.personal_handle", pa, severity_for(rules["qr.personal_handle"]),
               label="Personal mobile-number UPI ID promising you money", params={"upi": pa})

    if shop_name and pn:
        if _similarity(shop_name, pn) < NAME_MATCH_MIN:
            ev.add("qr", "qr.name_mismatch", f'QR says "{pn}", shop is "{shop_name}"',
                   severity_for(rules["qr.name_mismatch"]),
                   label="Name in QR does not match the shop", params={"pn": pn, "shop": shop_name})
        else:
            ev.add("qr", "info.name_match", f'QR says "{pn}", you expect "{shop_name}"',
                   label="Name in QR matches who you expect to pay (a good sign)")

    record = verify_upi_id(pa)
    meta["registry"] = {"is_mock": IS_MOCK, "found": bool(record)}
    if record:
        registered = record["registered_name"]
        meta["registry"]["registered_name"] = registered
        claimed = pn or shop_name
        if claimed and _similarity(registered, claimed) < REGISTRY_MATCH_MIN:
            ev.add("qr", "qr.registry_mismatch", f'Registered to "{registered}"',
                   severity_for(rules["qr.registry_mismatch"]),
                   label="Registered name differs from QR (demo data)",
                   params={"registered": registered, "pn": claimed})
        else:
            ev.add("qr", "info.registry_match", f'Registered to "{registered}"',
                   label="Registered name matches (demo data)")

    return {"kind": "qr", "meta": meta, "evidence": ev.items}


def analyze_qr_image(data: bytes, shop_name: str | None = None) -> dict:
    result = analyze_qr(decode_qr_image(data), shop_name)
    result["meta"]["source"] = "image"
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Inspect a UPI QR code.")
    ap.add_argument("input", help="QR image path or a upi:// link")
    ap.add_argument("--shop", default=None, help="Name of the shop you think you are paying")
    args = ap.parse_args()
    try:
        p = Path(args.input)
        if p.exists():
            out = analyze_qr_image(p.read_bytes(), args.shop)
        else:
            out = analyze_qr(args.input, args.shop)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
