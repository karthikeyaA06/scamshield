"""List the license of every Python package ScamShield installs, and flag problems.

Walks requirements.txt and all of its dependencies in the current environment, then
prints a Markdown table (used in THIRD_PARTY_LICENSES.md). Exits with code 1 if a
package has an unknown license or a strong copyleft (GPL/AGPL) license.

Usage (from the repo root, with the project's environment active):
    python tools/check_licenses.py
"""

from __future__ import annotations

import importlib.metadata as md
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Package metadata is sometimes wrong or vague. These were checked against the license
# file shipped inside each package.
VERIFIED = {
    "androguard": "Apache-2.0",          # classifier says "Other/Proprietary"; LICENCE-2.0 is Apache-2.0
    "qrcode": "BSD-3-Clause",            # classifier lists "Other/Proprietary"; LICENSE is BSD (Lincoln Loop)
    "zxing-cpp": "Apache-2.0",
    "pillow": "MIT-CMU",
    "rapidfuzz": "MIT",
    "mutf8": "MIT",
    "opencv-python-headless": "Apache-2.0 (bundled libraries: see its LICENSE-3RD-PARTY.txt)",
    "certifi": "MPL-2.0 (used unmodified)",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _direct_requirements() -> list[str]:
    names = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            names.append(re.split(r"[\s;<>=!~\[]", line, maxsplit=1)[0])
    if any(_norm(n) == "qrcode" for n in names):
        names.append("pillow")  # pulled in by qrcode[pil]
    return names


def _license(dist) -> str:
    name = _norm(dist.metadata["Name"])
    if name in VERIFIED:
        return VERIFIED[name]
    m = dist.metadata
    if m.get("License-Expression"):
        return m["License-Expression"]
    classifiers = [c.split("::")[-1].strip() for c in (m.get_all("Classifier") or [])
                   if c.startswith("License ::")]
    if classifiers:
        return "; ".join(classifiers)
    text = (m.get("License") or "").strip()
    return text.splitlines()[0][:60] if text else "UNKNOWN"


def collect() -> tuple[list[tuple], list[str]]:
    direct = {_norm(n) for n in _direct_requirements()}
    seen: dict[str, object] = {}
    missing: list[str] = []

    def walk(name: str) -> None:
        key = _norm(name)
        if key in seen:
            return
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            seen[key] = None
            missing.append(name)
            return
        seen[key] = dist
        for req in dist.requires or []:
            if "extra ==" in req:
                continue
            walk(re.split(r"[\s;<>=!~\[(]", req, maxsplit=1)[0])

    for name in _direct_requirements():
        walk(name)
    rows = []
    for key, dist in sorted(seen.items()):
        if dist is None:
            continue
        rows.append((dist.metadata["Name"], dist.version, _license(dist),
                     "direct" if key in direct else "dependency"))
    return rows, missing


def main() -> int:
    rows, missing = collect()
    print("| Package | Version | License | Used as |")
    print("|---|---|---|---|")
    for name, version, lic, role in rows:
        print(f"| {name} | {version} | {lic} | {role} |")
    if missing:
        print(f"\nNot installed on this platform (optional or OS-specific): {', '.join(sorted(missing))}")
    problems = [r for r in rows if r[2] == "UNKNOWN" or re.search(r"(?<!L)GPL", r[2])]
    if problems:
        print("\nREVIEW NEEDED:", ", ".join(f"{p[0]} ({p[2]})" for p in problems), file=sys.stderr)
        return 1
    print(f"\nAll {len(rows)} packages use permissive or weak-copyleft licenses. No GPL/AGPL found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
