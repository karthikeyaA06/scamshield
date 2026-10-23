"""Check a pasted SMS / WhatsApp message for scam signs -> evidence JSON.

The message is only read as text. Links in it are never opened.

Usage:
    python analyze_sms.py "message text" [--sender "AX-HDFCBK"]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

try:
    from .common import EvidenceBuilder, InputError, load_asset, severity_for
except ImportError:  # pragma: no cover
    from common import EvidenceBuilder, InputError, load_asset, severity_for

MAX_CHARS = 4000

# Bare domains like "sbi-kyc.in/login" count as links too, not just http(s) URLs.
LINK_RE = re.compile(
    r"(?:(?:https?://)|(?:www\.))[^\s<>\"']+|\b[a-z0-9][a-z0-9-]{1,62}(?:\.[a-z0-9-]{2,63})*\."
    r"(?:com|in|net|org|info|xyz|top|online|site|live|club|co|me|io|app|link|cc|ly|gd|id|asia|"
    r"click|shop|store|vip|icu|buzz|example)(?:/[^\s<>\"']*)?", re.I)
PERSONAL_NUMBER_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
SENDER_HEADER_RE = re.compile(r"^[A-Z]{2}-[A-Z0-9]{6}(?:-[STPG])?$", re.I)

KEYWORDS = {
    "urgency": ["immediately", "urgent", "within 24 hours", "within 24 hrs", "within 2 hours",
                "last chance", "last date", "expire", "expires", "expiring", "blocked", "suspended",
                "deactivated", "disconnected", "will be closed", "act now", "final notice",
                "ತಕ್ಷಣ", "ಇಂದು", "ಬ್ಲಾಕ್", "तुरंत", "आज ही"],
    "secret": ["otp", "pin", "cvv", "password", "passcode", "mpin", "upi pin", "card number",
               "net banking", "login id", "aadhaar number", "pan number", "bank details",
               "account details", "account number", "card details"],
    "ask": ["share", "send", "tell", "reply with", "provide", "enter", "update", "verify", "confirm",
            "submit", "forward"],
    "dont_share": ["do not share", "don't share", "dont share", "never share", "never ask",
                   "will never ask", "not share"],
    # "refund" and "cashback" alone are normal in genuine shopping messages; "claim your ..." is not.
    "money_lure": ["won", "winner", "lottery", "prize", "reward points expire", "lucky draw",
                   "kbc", "free gift", "claim your", "jackpot", "ಬಹುಮಾನ", "ಗೆದ್ದಿದ್ದೀರಿ"],
    "kyc": ["kyc", "pan card", "pan update", "update pan", "re-kyc", "ekyc", "e-kyc",
            "account will be blocked", "account will be suspended", "a/c will be blocked"],
    "job": ["part time", "part-time", "work from home", "daily income", "earn rs", "earn ₹",
            "per day", "like youtube", "youtube videos", "rate hotels", "telegram task", "simple tasks",
            "daily salary", "hiring"],
    "authority": ["cbi", "police", "cyber crime branch", "crime branch", "customs", "narcotics",
                  "ncb", "enforcement directorate", "money laundering", "arrest", "warrant", "court",
                  "drugs", "illegal parcel", "fedex", "trai", "sim will be blocked"],
    "power": ["electricity", "power will be", "power supply", "bijli", "ವಿದ್ಯುತ್", "light bill",
              "electricity bill", "bescom"],
}


def _find(text: str, words: list[str]) -> list[str]:
    low = text.lower()
    found = []
    for w in words:
        if re.match(r"^[a-z0-9 ₹/'-]+$", w):
            if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
                found.append(w)
        elif w in text:  # Kannada / Hindi keywords: plain substring
            found.append(w)
    return found


def _host_of(link: str) -> str:
    url = link if re.match(r"^https?://", link, re.I) else "http://" + link
    return (urlparse(url).hostname or "").lower().strip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in ("co.in", "gov.in", "nic.in", "bank.in", "org.in", "net.in"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _lookalike(host: str, data: dict) -> str | None:
    """Return the brand a link imitates, if its domain is not that brand's official site."""
    if any(host == s or host.endswith("." + s) for s in data["official_suffixes"]):
        return None
    reg = _registered_domain(host)
    tokens = re.split(r"[.\-_]", host)
    for brand, officials in data["brands"].items():
        if brand in tokens or brand in host.replace(".", "-").split("-"):
            if reg in officials or any(host == o or host.endswith("." + o) for o in officials):
                return None
            return brand
    return None


def analyze_sms(text: str, sender: str | None = None) -> dict:
    text = (text or "").strip()
    if not text:
        raise InputError("Paste the message you want to check.")
    text = text[:MAX_CHARS]
    sender = (sender or "").strip()[:60] or None
    rules = load_asset("rules.json")["rules"]
    domains = load_asset("official_domains.json")
    ev = EvidenceBuilder()
    meta = {"message": text, "sender": sender, "length": len(text)}

    # Sender
    claims_org = bool(_find(text, KEYWORDS["kyc"] + KEYWORDS["authority"] + KEYWORDS["power"])) or bool(
        re.search(r"\b(bank|sbi|hdfc|icici|axis|kotak|paytm|phonepe|india ?post|income ?tax|rto|"
                  r"parivahan|aadhaar|uidai|amazon|flipkart|department|govt|government)\b", text, re.I))
    if sender:
        compact = re.sub(r"[\s-]", "", sender)
        if SENDER_HEADER_RE.match(sender):
            ev.add("sender", "info.sender_header", sender, label="Sent from a registered business sender ID")
        elif re.fullmatch(r"(\+?91)?[6-9]\d{9}", compact):
            if claims_org:
                ev.add("sender", "sms.personal_sender", sender, severity_for(rules["sms.personal_sender"]),
                       label="Claims to be an organisation but came from a personal number",
                       params={"sender": sender})
            else:
                ev.add("sender", "info.sender_personal", sender, label="Sent from a personal mobile number")
        else:
            ev.add("sender", "info.sender", sender, label="Sender")

    # Links
    seen: set[str] = set()
    for raw in LINK_RE.findall(text):
        link = raw.rstrip(".,;:!?)\"'")
        host = _host_of(link)
        if not host or host in seen:
            continue
        seen.add(host)
        path = link.lower()
        if _is_ip(host):
            ev.add("link", "string.raw_ip", link, severity_for(rules["string.raw_ip"]),
                   label="Link to a bare IP address", params={"host": host})
        elif host in domains["shorteners"]:
            ev.add("link", "sms.short_link", link, severity_for(rules["sms.short_link"]),
                   label="Short link that hides the real website", params={"host": host})
        elif host in domains["chat_hosts"]:
            ev.add("link", "sms.chat_link", link, severity_for(rules["sms.chat_link"]),
                   label="Link to a private WhatsApp or Telegram chat")
        else:
            brand = _lookalike(host, domains)
            if brand:
                ev.add("link", "sms.lookalike_domain", link, severity_for(rules["sms.lookalike_domain"]),
                       label=f"Website pretending to be {brand.upper()}",
                       params={"host": host, "brand": brand.upper()})
            else:
                ev.add("link", "info.link", link, label="Web link in the message")
        if re.search(r"\.apk(?:$|[?#])", path):
            ev.add("link", "sms.apk_link", link, severity_for(rules["sms.apk_link"]),
                   label="Link downloads an app file (.apk)")

    # Content signals
    def add_kw(key: str, group: str, label: str):
        hits = _find(text, KEYWORDS[group])
        if hits:
            ev.add("text", key, ", ".join(hits[:5]), severity_for(rules[key]), label=label,
                   params={"words": ", ".join(hits[:3])})
        return hits

    urgency = add_kw("sms.urgency", "urgency", "Pressure to act fast")

    secrets = _find(text, KEYWORDS["secret"])
    asks = _find(text, KEYWORDS["ask"])
    safe_otp = _find(text, KEYWORDS["dont_share"])
    if secrets and asks and not safe_otp:
        ev.add("text", "sms.asks_secret", ", ".join(secrets[:4]), severity_for(rules["sms.asks_secret"]),
               label="Asks for secret codes or details", params={"words": ", ".join(secrets[:3])})
    elif secrets and safe_otp:
        ev.add("text", "info.otp_notice", ", ".join(safe_otp[:2]),
               label="Warns you not to share codes (normal for genuine OTP messages)")

    add_kw("sms.money_lure", "money_lure", "Promises money or prizes")
    add_kw("sms.kyc_update", "kyc", "Threatens to block your account over KYC/PAN")
    add_kw("sms.job_scam", "job", "Easy-money job offer")
    add_kw("sms.authority_threat", "authority", "Threats in the name of police or officials")
    power = _find(text, KEYWORDS["power"])
    if power and (urgency or re.search(r"disconnect|cut|ಕಡಿತ", text, re.I)):
        ev.add("text", "sms.power_cut", ", ".join(power[:3]), severity_for(rules["sms.power_cut"]),
               label="Threatens to cut your electricity")

    # Asking you to call a mobile number only matters when the message claims to be an
    # organisation or promises money; a friend saying "call me" is normal.
    lure = bool(_find(text, KEYWORDS["money_lure"] + KEYWORDS["job"]))
    numbers = [m.group(0) for m in PERSONAL_NUMBER_RE.finditer(text)]
    if numbers and (claims_org or lure) and re.search(r"\b(call|contact|whatsapp|reach|dial|ring)\b", text, re.I):
        ev.add("text", "sms.call_number", numbers[0], severity_for(rules["sms.call_number"]),
               label="Asks you to call a personal mobile number", params={"number": numbers[0]})

    return {"kind": "sms", "meta": meta, "evidence": ev.items}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Check a suspicious SMS or WhatsApp message.")
    ap.add_argument("text", help="The message text")
    ap.add_argument("--sender", default=None, help="Sender ID or number, e.g. AX-HDFCBK or +9198...")
    args = ap.parse_args()
    try:
        print(json.dumps(analyze_sms(args.text, args.sender), indent=2, ensure_ascii=False))
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
