"""Every installed dependency must have a known, non-GPL license, and the license files must exist."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from check_licenses import collect  # noqa: E402


def test_no_unknown_or_gpl_dependencies():
    rows, _ = collect()
    assert rows, "no dependencies found"
    bad = [r for r in rows if r[2] == "UNKNOWN" or ("GPL" in r[2] and "LGPL" not in r[2])]
    assert not bad, bad


def test_license_files_present():
    for name in ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md", "app/static/fonts/OFL-Anek.txt"]:
        assert (ROOT / name).exists(), name
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    assert "license: Apache-2.0" in (ROOT / "skills/scamshield/SKILL.md").read_text()
