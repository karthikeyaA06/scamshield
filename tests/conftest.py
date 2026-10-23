import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "scamshield"))
sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLES = ROOT / "samples" / "out"


@pytest.fixture
def fixture():
    def load(name: str) -> dict:
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return load


@pytest.fixture(scope="session", autouse=True)
def demo_samples():
    """Build the harmless demo samples if they are missing."""
    if not (SAMPLES / "samples.json").exists():
        from samples.make_demo_samples import main
        main()
    return SAMPLES


@pytest.fixture(autouse=True)
def clear_model_cache():
    """Each test starts with an empty model-answer cache."""
    from scripts import explain
    explain._CACHE.clear()
    yield
    explain._CACHE.clear()
