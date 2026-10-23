"""ScamShield web app: FastAPI backend + static frontend.

Run:
    uvicorn app.server:app --port 8000
then open http://localhost:8000

Everything runs on this computer. The only network call is to the local
Ollama server (default http://localhost:11434).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "scamshield"))

from scripts.analyze_file import analyze_file  # noqa: E402
from scripts.analyze_qr import analyze_qr, analyze_qr_image  # noqa: E402
from scripts.analyze_sms import analyze_sms  # noqa: E402
from scripts.common import InputError, MAX_APK_BYTES, MAX_IMAGE_BYTES  # noqa: E402
from scripts.explain import explain, model_status, warm_up  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
SAMPLES_DIR = ROOT / "samples" / "out"
USE_MODEL = os.environ.get("SCAMSHIELD_NO_MODEL", "").lower() not in ("1", "true", "yes")
REPO_URL = os.environ.get("SCAMSHIELD_REPO_URL", "")
VERSION = "1.2.0"


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Load Gemma into memory in the background so the first scan is fast.
    if USE_MODEL and os.environ.get("SCAMSHIELD_NO_WARMUP", "") != "1":
        threading.Thread(target=warm_up, daemon=True).start()
    yield


app = FastAPI(title="ScamShield", version=VERSION, docs_url="/api/docs", redoc_url=None,
              lifespan=lifespan)


@app.exception_handler(InputError)
async def _input_error(_: Request, exc: InputError):
    return JSONResponse(status_code=422, content={"error": str(exc)})


def _load_samples() -> list[dict]:
    path = SAMPLES_DIR / "samples.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["samples"]


def _sample(sample_id: str) -> dict:
    for s in _load_samples():
        if s["id"] == sample_id:
            return s
    raise HTTPException(status_code=404, detail="Unknown sample")


def _run(analysis: dict) -> dict:
    return explain(analysis, use_model=USE_MODEL)


# ---------------------------------------------------------------- API
@app.get("/api/health")
def health() -> dict:
    status = model_status() if USE_MODEL else {"reachable": False, "installed": False,
                                                "model": "disabled", "host": ""}
    return {"version": VERSION, "model": status, "model_enabled": USE_MODEL, "repo_url": REPO_URL}


@app.get("/api/samples")
def samples() -> dict:
    return {"samples": _load_samples()}


@app.get("/api/samples/{sample_id}/file")
def sample_file(sample_id: str):
    s = _sample(sample_id)
    if "file" not in s:
        raise HTTPException(status_code=404, detail="This sample has no file")
    media = {"apk": "application/vnd.android.package-archive",
             "exe": "application/octet-stream"}.get(s["kind"], "image/png")
    return FileResponse(SAMPLES_DIR / s["file"], media_type=media, filename=s["file"])


@app.post("/api/samples/{sample_id}/check")
def check_sample(sample_id: str) -> dict:
    s = _sample(sample_id)
    if s["kind"] == "sms":
        result = _run(analyze_sms(s["text"], s.get("sender")))
        result["sample_id"] = sample_id
        return result
    path = SAMPLES_DIR / s["file"]
    if s["kind"] in ("apk", "exe"):
        analysis = analyze_file(path, s["file"])
    else:
        analysis = analyze_qr_image(path.read_bytes(), s.get("shop_name") or None)
        analysis["meta"]["preview"] = f"/api/samples/{sample_id}/file"
    result = _run(analysis)
    result["sample_id"] = sample_id
    return result


@app.post("/api/check/apk")
@app.post("/api/check/file")
def check_file(file: UploadFile = File(...)) -> dict:
    """Android app or Windows program. The type is read from the file's bytes, not its name."""
    name = os.path.basename(file.filename or "upload")
    with tempfile.TemporaryDirectory(prefix="scamshield-") as tmp:
        dest = Path(tmp) / "upload.bin"
        written = 0
        with open(dest, "wb") as out:
            while chunk := file.file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_APK_BYTES:
                    raise InputError("The file is larger than 100 MB, so ScamShield will not open it.")
                out.write(chunk)
        analysis = analyze_file(dest, name)
    return _run(analysis)


@app.post("/api/check/sms")
def check_sms(text: str = Form(""), sender: str = Form("")) -> dict:
    """A pasted SMS or WhatsApp message. Links inside it are never opened."""
    return _run(analyze_sms(text, sender))


@app.post("/api/check/qr")
def check_qr(file: UploadFile | None = File(None), link: str = Form(""),
             shop_name: str = Form("")) -> dict:
    shop = shop_name.strip()[:120] or None
    if file is not None and file.filename:
        data = file.file.read(MAX_IMAGE_BYTES + 1)
        analysis = analyze_qr_image(data, shop)
    elif link.strip():
        analysis = analyze_qr(link.strip()[:2000], shop)
        analysis["meta"]["source"] = "link"
    else:
        raise InputError("Add a QR image or paste a UPI link to check.")
    return _run(analysis)


# ---------------------------------------------------------------- frontend
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
