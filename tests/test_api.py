"""Web API. The model is switched off so tests never need Ollama."""

import pytest
from fastapi.testclient import TestClient

import app.server as server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "USE_MODEL", False)
    return TestClient(server.app)


def test_home_page(client):
    res = client.get("/")
    assert res.status_code == 200 and "Check before you trust." in res.text


def test_health(client):
    body = client.get("/api/health").json()
    assert body["model_enabled"] is False


def test_samples_list_and_check(client):
    samples = client.get("/api/samples").json()["samples"]
    assert {s["id"] for s in samples} >= {"apk_fake", "qr_cashback"}
    res = client.post("/api/samples/apk_fake/check")
    assert res.status_code == 200 and res.json()["verdict"] == "Dangerous"


def test_upload_apk(client, demo_samples):
    with open(demo_samples / "simple_calculator.apk", "rb") as fh:
        res = client.post("/api/check/apk", files={"file": ("calc.apk", fh, "application/octet-stream")})
    assert res.status_code == 200
    assert res.json()["verdict"] == "Safe" and res.json()["meta"]["file_name"] == "calc.apk"


def test_upload_qr_image_with_shop(client, demo_samples):
    with open(demo_samples / "qr_sticker.png", "rb") as fh:
        res = client.post("/api/check/qr", files={"file": ("qr.png", fh, "image/png")},
                          data={"shop_name": "Sharma General Store"})
    assert res.json()["verdict"] == "Suspicious"


def test_qr_link(client):
    res = client.post("/api/check/qr", data={"link": "upi://pay?pa=9900112233@paytm&am=999&tn=claim%20refund"})
    assert res.json()["verdict"] == "Dangerous"


def test_bad_inputs_return_readable_errors(client):
    res = client.post("/api/check/apk", files={"file": ("x.apk", b"hello", "application/octet-stream")})
    assert res.status_code == 422 and "APK" in res.json()["error"]
    res = client.post("/api/check/qr", data={"link": ""})
    assert res.status_code == 422
    res = client.post("/api/check/qr", files={"file": ("x.png", b"not an image", "image/png")})
    assert res.status_code == 422
    assert client.post("/api/samples/nope/check").status_code == 404


def test_upload_program_disguised_as_pdf(client, demo_samples):
    data = (demo_samples / "PhotoViewer_Setup.exe").read_bytes()
    res = client.post("/api/check/apk", files={"file": ("Bank_Statement.pdf", data, "application/pdf")})
    body = res.json()
    assert res.status_code == 200 and body["kind"] == "exe" and body["verdict"] == "Dangerous"
    assert body["meta"]["file_name"] == "Bank_Statement.pdf"


def test_check_message(client):
    res = client.post("/api/check/sms", data={
        "text": "Dear SBI user, your account will be blocked today. Update KYC immediately: http://sbi-kyc.example/login",
        "sender": "+917012345678"})
    body = res.json()
    assert res.status_code == 200 and body["kind"] == "sms" and body["verdict"] == "Dangerous"
    assert client.post("/api/check/sms", data={"text": ""}).status_code == 422
    assert client.post("/api/samples/sms_otp/check").json()["verdict"] == "Safe"
    assert client.get("/api/samples/sms_otp/file").status_code == 404
