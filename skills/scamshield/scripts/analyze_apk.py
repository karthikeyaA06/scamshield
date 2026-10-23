"""Static analysis of an Android APK -> evidence JSON.

SAFETY: this script never installs, executes or emulates the APK. It only reads
the file as a ZIP archive and parses its manifest, signing certificate and code
strings.

Usage:
    python analyze_apk.py path/to/app.apk
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

try:  # these imports work both as a package (app server) and as a script
    from .common import (EvidenceBuilder, InputError, MAX_APK_BYTES, load_asset,
                         severity_for)
except ImportError:  # pragma: no cover
    from common import (EvidenceBuilder, InputError, MAX_APK_BYTES, load_asset,
                        severity_for)

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,200}")
IGNORED_HOSTS = {
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "xmlpull.org",
    "www.apache.org", "apache.org", "play.google.com", "developer.android.com",
}
SENSITIVE_WORDS = ["otp", "upi", "kyc", "challan", "refund", "cvv", "aadhaar",
                   "pan card", "debit card", "net banking", "pin"]
# Known commercial/open packers. Their presence means the real code is hidden.
PACKER_SIGNATURES = {
    "libjiagu": "Jiagu (360)",
    "com.stub.stubapp": "Jiagu (360)",
    "libsecexe": "Bangcle",
    "com.secneo": "Bangcle/SecNeo",
    "libdexhelper": "DexHelper",
    "com.tencent.stubshell": "Tencent Legu",
    "libshell": "Tencent Legu",
    "com.ali.mobisecenhance": "Alibaba",
    "libapktoolplus": "ApkToolPlus",
}
TEXT_SCAN_SUFFIXES = (".json", ".txt", ".xml", ".properties", ".js", ".html", ".cfg", ".conf")


def _short_perm(perm: str) -> str:
    return perm.rsplit(".", 1)[-1]


def _silence_androguard() -> None:
    try:
        from loguru import logger
        logger.remove()
    except Exception:  # pragma: no cover
        pass


def _validate(path: Path) -> None:
    if not path.exists():
        raise InputError(f"File not found: {path}")
    size = path.stat().st_size
    if size == 0:
        raise InputError("The file is empty.")
    if size > MAX_APK_BYTES:
        raise InputError("The file is larger than 100 MB, so ScamShield will not open it.")
    if not zipfile.is_zipfile(path):
        raise InputError("This is not an Android app file (APK). APKs are ZIP archives.")
    with zipfile.ZipFile(path) as zf:
        if "AndroidManifest.xml" not in zf.namelist():
            raise InputError("This ZIP file has no AndroidManifest.xml, so it is not an APK.")


def _collect_strings(apk, zf: zipfile.ZipFile) -> tuple[list[str], int]:
    """Return (strings, dex_count). Reads DEX string tables plus small text assets."""
    from androguard.core.dex import DEX

    strings: list[str] = []
    dex_count = 0
    for raw in apk.get_all_dex():
        dex_count += 1
        try:
            for s in DEX(raw).get_strings():
                strings.append(s if isinstance(s, str) else s.decode("utf-8", "ignore"))
        except Exception:
            # Malformed DEX: fall back to a raw byte scan of that blob.
            strings.extend(m.decode("ascii", "ignore") for m in URL_RE.findall(raw))
    for info in zf.infolist():
        name = info.filename.lower()
        if info.file_size > 2 * 1024 * 1024:
            continue
        if name.startswith("assets/") or name.endswith(TEXT_SCAN_SUFFIXES):
            if name.endswith(".dex") or name == "androidmanifest.xml":
                continue
            data = zf.read(info)
            strings.extend(m.decode("ascii", "ignore") for m in URL_RE.findall(data))
    return strings, dex_count


def _classify_urls(strings: list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"telegram": [], "raw_ip": [], "firebase": [], "other": []}
    seen: set[str] = set()
    for s in strings:
        for m in URL_RE.findall(s.encode("utf-8", "ignore")):
            url = m.decode("ascii", "ignore").rstrip(".,;)\"'")
            if url in seen:
                continue
            seen.add(url)
            host = (urlparse(url).hostname or "").lower()
            if not host or host in IGNORED_HOSTS:
                continue
            if host == "api.telegram.org" and "/bot" in url:
                found["telegram"].append(url)
            elif _is_ip(host):
                found["raw_ip"].append(url)
            elif host.endswith("firebaseio.com"):
                found["firebase"].append(url)
            else:
                found["other"].append(url)
    return found


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _service_permissions(apk) -> list[str]:
    """Permissions declared on <service android:permission=...> (e.g. accessibility)."""
    out: list[str] = []
    try:
        manifest = apk.get_android_manifest_xml()
        ns = "{http://schemas.android.com/apk/res/android}"
        for svc in manifest.iter("service"):
            perm = svc.get(ns + "permission")
            if perm:
                out.append(perm)
    except Exception:
        pass
    return out


def _cert_info(apk) -> dict:
    info = {"signed": False, "subject": "", "issuer": "", "self_signed": False, "debug": False}
    try:
        info["signed"] = bool(apk.is_signed())
        certs = apk.get_certificates()
    except Exception:
        certs = []
    if certs:
        cert = certs[0]
        subject = cert.subject.human_friendly
        issuer = cert.issuer.human_friendly
        info.update(subject=subject, issuer=issuer, signed=True,
                    self_signed=(subject == issuer),
                    debug=("android debug" in subject.lower()))
    return info


def _impersonation(label: str, package: str) -> tuple[str, str] | None:
    data = load_asset("impersonation_keywords.json")
    if package in data["official_packages"]:
        return None
    haystack = f"{label} {package}".lower().replace("_", " ").replace(".", " ")
    for word, entity in data["keywords"].items():
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", haystack):
            return word, entity
    return None


def analyze_apk(path: str | Path) -> dict:
    path = Path(path)
    _validate(path)
    _silence_androguard()
    from androguard.core.apk import APK

    rules = load_asset("rules.json")["rules"]
    risky = load_asset("high_risk_permissions.json")

    try:
        apk = APK(str(path))
    except Exception as exc:
        raise InputError(f"The APK could not be read: {exc}") from exc

    ev = EvidenceBuilder()
    package = apk.get_package() or "unknown"
    label = apk.get_app_name() or package
    meta = {
        "package": package,
        "label": label,
        "version": apk.get_androidversion_name() or "",
        "min_sdk": apk.get_min_sdk_version() or "",
        "target_sdk": apk.get_target_sdk_version() or "",
        "file_name": path.name,
        "size_bytes": path.stat().st_size,
    }
    ev.add("app", "info.label", label, label="App name shown to the user")
    ev.add("app", "info.package", package, label="Package name")

    # Permissions (uses-permission + service-bound permissions such as accessibility)
    perms = list(dict.fromkeys(list(apk.get_permissions()) + _service_permissions(apk)))
    for perm in perms:
        short = _short_perm(perm)
        key = f"perm.{short}"
        if short in risky:
            ev.add("permission", key, perm, severity_for(rules.get(key, 0)), label=risky[short])
    other_perms = [p for p in perms if _short_perm(p) not in risky]
    if other_perms:
        ev.add("permission", "info.other_permissions", ", ".join(_short_perm(p) for p in other_perms),
               label="Other permissions (normal risk)")

    # Code strings and URLs
    with zipfile.ZipFile(path) as zf:
        strings, dex_count = _collect_strings(apk, zf)
        file_names = [n.lower() for n in zf.namelist()]
    urls = _classify_urls(strings)
    for url in urls["telegram"][:3]:
        ev.add("string", "string.telegram_bot", url, severity_for(rules["string.telegram_bot"]),
               label="Telegram bot link inside the code")
    for url in urls["raw_ip"][:3]:
        host = urlparse(url).hostname or url
        ev.add("string", "string.raw_ip", url, severity_for(rules["string.raw_ip"]),
               label="Connects to a bare IP address", params={"host": host})
    for url in urls["firebase"][:2]:
        ev.add("string", "string.firebase_db", url, severity_for(rules["string.firebase_db"]),
               label="Sends data to an online database")
    if urls["other"]:
        ev.add("string", "info.urls", ", ".join(urls["other"][:5]), label="Other web addresses in the code")

    lowered = " ".join(strings).lower()
    words = [w for w in SENSITIVE_WORDS if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", lowered)]
    if words:
        ev.add("string", "string.sensitive_keywords", ", ".join(words),
               severity_for(rules["string.sensitive_keywords"]),
               label="Sensitive words in the code", params={"words": ", ".join(words)})

    # Impersonation
    imp = _impersonation(label, package)
    if imp:
        word, entity = imp
        ev.add("app", "impersonation", f'"{label}" ({package}) matches "{word}"',
               severity_for(rules["impersonation"]),
               label=f"Name looks like an official {entity} app", params={"entity": entity})

    # Signing certificate
    cert = _cert_info(apk)
    if not cert["signed"]:
        ev.add("certificate", "cert.unsigned", "No signing certificate",
               severity_for(rules["cert.unsigned"]), label="App is not signed")
    else:
        if cert["debug"]:
            ev.add("certificate", "cert.debug", cert["subject"], severity_for(rules["cert.debug"]),
                   label="Signed with a test (debug) certificate")
        else:
            ev.add("certificate", "info.certificate", cert["subject"],
                   label="Signing certificate" + (" (self-signed)" if cert["self_signed"] else ""))

    # Hidden code
    blob = " ".join(file_names) + " " + lowered
    packers = sorted({name for sig, name in PACKER_SIGNATURES.items() if sig in blob})
    if packers:
        ev.add("code", "code.packer", ", ".join(packers), severity_for(rules["code.packer"]),
               label="Uses a code-hiding packer", params={"words": ", ".join(packers)})
    if dex_count == 0:
        ev.add("code", "code.no_dex", "No classes.dex found", severity_for(rules["code.no_dex"]),
               label="No normal app code found")

    return {"kind": "apk", "meta": meta, "evidence": ev.items, "certificate": cert}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    try:
        print(json.dumps(analyze_apk(sys.argv[1]), indent=2, ensure_ascii=False))
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
