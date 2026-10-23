"""Static check of a Windows program (.exe / PE file) -> evidence JSON.

SAFETY: this script never runs the program. It reads the file's bytes: the PE
header, section names, signature directory and readable strings.

It also catches disguises: "receipt.pdf.exe", a program renamed to ".apk" or
".pdf", and names that hide the real extension with a right-to-left character.

Usage:
    python analyze_exe.py path/to/file.exe
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

try:
    from .analyze_apk import SENSITIVE_WORDS, _classify_urls, _impersonation
    from .common import EvidenceBuilder, InputError, MAX_APK_BYTES, load_asset, severity_for
except ImportError:  # pragma: no cover
    from analyze_apk import SENSITIVE_WORDS, _classify_urls, _impersonation
    from common import EvidenceBuilder, InputError, MAX_APK_BYTES, load_asset, severity_for

PROGRAM_EXTS = {"exe", "scr", "com", "pif", "msi", "bat", "cmd"}
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4", "mp3",
              "zip", "apk", "rtf", "ppt", "pptx"}
KEYLOGGER_APIS = ["GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW", "GetKeyboardState"]
PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".themida": "Themida",
                   ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
                   ".mpress1": "MPRESS", "MPRESS1": "MPRESS"}
RLO = "‮"
ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _parse_pe(data: bytes) -> dict:
    """Read just enough of the PE header: sections and whether a signature is attached."""
    info = {"is_pe": False, "sections": [], "signed": False, "arch": ""}
    if len(data) < 0x40:
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return info
    info["is_pe"] = True
    machine, n_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    info["arch"] = {0x14C: "32-bit", 0x8664: "64-bit", 0xAA64: "ARM64"}.get(machine, hex(machine))
    opt = e_lfanew + 24
    if opt + 2 <= len(data):
        magic = struct.unpack_from("<H", data, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        sec_dir = dirs + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY
        if sec_dir + 8 <= len(data) and dirs <= opt + opt_size:
            _, size = struct.unpack_from("<II", data, sec_dir)
            info["signed"] = size > 0
    sec_table = opt + opt_size
    for i in range(min(n_sections, 96)):
        start = sec_table + i * 40
        if start + 8 > len(data):
            break
        info["sections"].append(data[start:start + 8].rstrip(b"\0").decode("ascii", "ignore"))
    return info


def _name_tricks(name: str) -> dict:
    """Look for extension disguises in the file name."""
    out = {"hidden_char": RLO in name, "double": None, "renamed": None}
    clean = name.replace(RLO, "").strip().lower()
    parts = [p.strip() for p in clean.split(".")]
    if len(parts) >= 3 and parts[-1] in PROGRAM_EXTS and parts[-2] in DECOY_EXTS:
        out["double"] = parts[-2]
    elif len(parts) >= 2 and parts[-1] not in PROGRAM_EXTS:
        out["renamed"] = parts[-1]
    elif len(parts) == 1:
        out["renamed"] = "(no extension)"
    return out


def analyze_exe(path: str | Path, original_name: str | None = None) -> dict:
    path = Path(path)
    name = original_name or path.name
    size = path.stat().st_size
    if size > MAX_APK_BYTES:
        raise InputError("The file is larger than 100 MB, so ScamShield will not open it.")
    data = path.read_bytes()
    if not data.startswith(b"MZ"):
        raise InputError("This is not a Windows program (.exe).")

    rules = load_asset("rules.json")["rules"]
    pe = _parse_pe(data)
    ev = EvidenceBuilder()
    meta = {"file_name": name, "size_bytes": size, "label": name, "package": "",
            "arch": pe["arch"], "is_pe": pe["is_pe"]}

    ev.add("program", "exe.windows_program", f"{name} ({pe['arch'] or 'DOS'} Windows program)",
           severity_for(rules["exe.windows_program"]), label="This file is a Windows program")

    tricks = _name_tricks(name)
    if tricks["hidden_char"]:
        ev.add("name", "exe.hidden_name", repr(name), severity_for(rules["exe.hidden_name"]),
               label="File name hides its real extension")
    if tricks["double"]:
        ev.add("name", "exe.double_extension", name, severity_for(rules["exe.double_extension"]),
               label=f"Pretends to be a .{tricks['double']} file",
               params={"name": name, "fake": tricks["double"].upper()})
    elif tricks["renamed"]:
        ev.add("name", "exe.disguised_extension", name, severity_for(rules["exe.disguised_extension"]),
               label=f"A program renamed to look like .{tricks['renamed']}",
               params={"ext": tricks["renamed"]})

    imp = _impersonation(name.rsplit(".", 1)[0], "")
    if imp:
        word, entity = imp
        ev.add("program", "impersonation", f'"{name}" matches "{word}"', severity_for(rules["impersonation"]),
               label=f"Name looks like an official {entity} file", params={"entity": entity})

    strings = [m.decode("ascii", "ignore") for m in ASCII_STR_RE.findall(data[:20_000_000])]
    joined = "\n".join(strings)

    hooks = [api for api in KEYLOGGER_APIS if api in joined]
    if hooks:
        ev.add("code", "exe.keylogger_api", ", ".join(hooks), severity_for(rules["exe.keylogger_api"]),
               label="Can record every key pressed")

    urls = _classify_urls(strings)
    for url in urls["telegram"][:3]:
        ev.add("string", "string.telegram_bot", url, severity_for(rules["string.telegram_bot"]),
               label="Telegram bot link inside the program")
    for url in urls["raw_ip"][:3]:
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        ev.add("string", "string.raw_ip", url, severity_for(rules["string.raw_ip"]),
               label="Connects to a bare IP address", params={"host": host})
    if urls["other"]:
        ev.add("string", "info.urls", ", ".join(urls["other"][:5]), label="Other web addresses in the program")

    low = joined.lower()
    words = [w for w in SENSITIVE_WORDS if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low)]
    if words:
        ev.add("string", "string.sensitive_keywords", ", ".join(words),
               severity_for(rules["string.sensitive_keywords"]),
               label="Sensitive words in the program", params={"words": ", ".join(words)})

    packers = sorted({PACKER_SECTIONS[s] for s in pe["sections"] if s in PACKER_SECTIONS})
    if packers:
        ev.add("code", "exe.packer", ", ".join(packers), severity_for(rules["exe.packer"]),
               label="Uses a code-hiding packer", params={"words": ", ".join(packers)})

    if pe["signed"]:
        ev.add("certificate", "info.signature", "Signature block present (not verified offline)",
               label="Has a publisher signature")
    else:
        ev.add("certificate", "exe.unsigned", "No publisher signature", severity_for(rules["exe.unsigned"]),
               label="No publisher signature")

    return {"kind": "exe", "meta": meta, "evidence": ev.items}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    try:
        print(json.dumps(analyze_exe(sys.argv[1]), indent=2, ensure_ascii=False))
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
