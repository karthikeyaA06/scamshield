"""Pick the right analyzer by looking at what a file really is, not what it is called.

APKs are ZIP archives (they start with "PK"); Windows programs start with "MZ".
Checking the first bytes means a program renamed to ".apk" or ".pdf" is still caught.

Usage:
    python analyze_file.py path/to/file [original_name]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from .analyze_apk import analyze_apk
    from .analyze_exe import analyze_exe
    from .common import InputError
except ImportError:  # pragma: no cover
    from analyze_apk import analyze_apk
    from analyze_exe import analyze_exe
    from common import InputError


def analyze_file(path: str | Path, original_name: str | None = None) -> dict:
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        raise InputError("The file is empty.")
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(b"MZ"):
        return analyze_exe(path, original_name)
    if head.startswith(b"PK"):
        result = analyze_apk(path)
        if original_name:
            result["meta"]["file_name"] = original_name
        return result
    raise InputError("This file is neither an Android app (APK) nor a Windows program (EXE).")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(2)
    try:
        out = analyze_file(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    except InputError as err:
        print(json.dumps({"error": str(err)}))
        sys.exit(1)
