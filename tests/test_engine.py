"""Analyzers, scoring and the model validator."""

import json

import pytest

from scripts import explain as ex
from scripts.analyze_apk import analyze_apk
from scripts.analyze_file import analyze_file
from scripts.analyze_sms import analyze_sms
from scripts.analyze_qr import analyze_qr, analyze_qr_image
from scripts.common import InputError
from scripts.score import score


# ------------------------------------------------------------------ demo samples
@pytest.mark.parametrize("sample_id", ["apk_fake", "apk_safe", "apk_kyc", "apk_pmkisan", "apk_loan",
                                       "exe_receipt", "exe_renamed", "exe_safe",
                                       "qr_shop", "qr_cashback", "qr_sticker",
                                       "sms_power", "sms_kyc", "sms_job", "sms_arrest", "sms_otp"])
def test_demo_samples_give_expected_verdicts(demo_samples, sample_id):
    meta = json.loads((demo_samples / "samples.json").read_text(encoding="utf-8"))
    sample = next(s for s in meta["samples"] if s["id"] == sample_id)
    if sample["kind"] == "sms":
        result = ex.explain(analyze_sms(sample["text"], sample.get("sender")), use_model=False)
        assert result["verdict"] == sample["expected"]
        return
    path = demo_samples / sample["file"]
    if sample["kind"] in ("apk", "exe"):
        analysis = analyze_file(path, sample["file"])
    else:
        analysis = analyze_qr_image(path.read_bytes(), sample.get("shop_name") or None)
    result = ex.explain(analysis, use_model=False)
    assert result["verdict"] == sample["expected"]
    assert result["next_steps_en"] and result["next_steps_kn"]


def test_fake_apk_evidence(fixture):
    keys = {e["key"] for e in fixture("apk_fake.json")["evidence"]}
    assert {"perm.READ_SMS", "perm.RECEIVE_SMS", "perm.BIND_ACCESSIBILITY_SERVICE",
            "string.telegram_bot", "impersonation", "cert.debug"} <= keys


# ------------------------------------------------------------------ scoring
def test_combos_and_cap(fixture):
    s = score(fixture("apk_fake.json"))
    rules = {h["rule"] for h in s["hits"]}
    assert {"combo.otp_theft", "combo.screen_takeover", "combo.fake_official_sms"} <= rules
    assert s["score"] == 100 and s["floor"] == "Dangerous"
    perm_total = sum(h["weight"] for h in s["hits"] if h["rule"].startswith("perm."))
    assert perm_total <= 45


def test_safe_apk_scores_zero(fixture):
    assert score(fixture("apk_safe.json"))["score"] == 0


def test_permissions_alone_cannot_reach_dangerous():
    evidence = [{"id": f"E{i}", "key": f"perm.{p}", "severity": "high"} for i, p in enumerate(
        ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG", "CALL_PHONE"], 1)]
    s = score({"kind": "apk", "evidence": evidence})
    assert s["floor"] != "Dangerous"


# ------------------------------------------------------------------ QR parsing
def test_qr_web_link_is_flagged():
    a = analyze_qr("https://pay-refund-kyc.example/login")
    assert any(e["key"] == "qr.web_link" for e in a["evidence"])


def test_qr_plain_text_is_safe():
    assert ex.explain(analyze_qr("hello world"), use_model=False)["verdict"] == "Safe"


def test_qr_without_payee_is_rejected():
    with pytest.raises(InputError):
        analyze_qr("upi://pay?pn=Someone")


def test_shop_name_matching_ignores_generic_words():
    same = analyze_qr("upi://pay?pa=x@okaxis&pn=SHARMA%20GEN%20STORE", "Sharma General Store")
    other = analyze_qr("upi://pay?pa=x@okaxis&pn=Sri%20Ganesh%20Stores", "Sharma General Store")
    assert not any(e["key"] == "qr.name_mismatch" for e in same["evidence"])
    assert any(e["key"] == "qr.name_mismatch" for e in other["evidence"])


def test_non_zip_apk_is_rejected(tmp_path):
    bad = tmp_path / "x.apk"
    bad.write_text("not a zip")
    with pytest.raises(InputError):
        analyze_apk(bad)


# ------------------------------------------------------------------ validator
def test_validator_drops_invented_evidence_ids(fixture):
    analysis = fixture("apk_fake.json")
    s = score(analysis)
    out = ex.validate({"verdict": "Dangerous", "reasons": [
        {"evidence_ids": ["E99"], "en": "Records your calls.", "kn": "x"},
        {"evidence_ids": ["E7", "E99"], "en": "Sends data to a Telegram bot.", "kn": ""},
    ]}, analysis, s)
    assert out["dropped_reasons"] == 1
    assert out["reasons"][0]["evidence_ids"] == ["E7"]
    assert out["reasons"][0]["kn"]  # filled from template or English


def test_model_cannot_lower_the_verdict(fixture, monkeypatch):
    analysis = fixture("apk_fake.json")
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Safe", "reasons": [],
                                                          "summary_en": "Looks fine."}, "ok", 5))
    result = ex.explain(analysis)
    assert result["verdict"] == "Dangerous"
    assert result["ai"]["raised_by_rules"] is True
    assert result["summary_en"] != "Looks fine."  # model summary discarded when overruled
    assert result["reasons"]  # rule reasons supplemented


def test_model_can_raise_the_verdict_with_real_evidence(monkeypatch):
    analysis = analyze_qr("upi://pay?pa=ganeshstores@okicici&pn=Sri%20Ganesh%20Stores",
                          "Sharma General Store")  # name mismatch -> Suspicious floor
    risk_id = next(e["id"] for e in analysis["evidence"] if e["key"] == "qr.name_mismatch")
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Dangerous", "reasons": [
        {"evidence_ids": [risk_id], "en": "Pays a different shop.", "kn": "ಬೇರೆ ಅಂಗಡಿಗೆ ಪಾವತಿ."}]}, "ok", 5))
    result = ex.explain(analysis)
    assert result["verdict"] == "Dangerous" and not result["ai"]["capped_by_rules"]


def test_model_cannot_raise_on_normal_details(fixture, monkeypatch):
    analysis = fixture("apk_safe.json")
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Suspicious", "reasons": [
        {"evidence_ids": ["E1"], "en": "Odd name.", "kn": "ವಿಚಿತ್ರ ಹೆಸರು."}]}, "ok", 5))
    result = ex.explain(analysis)
    assert result["verdict"] == "Safe" and result["ai"]["capped_by_rules"] is True


def test_genuine_personal_upi_qr_is_safe(monkeypatch):
    """A real person's PhonePe QR with a mobile-number UPI ID and a matching name."""
    analysis = analyze_qr("upi://pay?pa=9901919538@ibl&pn=KARTHIKEYA%20R", "karthikeya")
    keys = {e["key"] for e in analysis["evidence"]}
    assert "qr.personal_handle" not in keys and "info.name_match" in keys
    payee = next(e["id"] for e in analysis["evidence"] if e["key"] == "info.payee_upi")
    # Even if the model over-reacts to the mobile-number UPI ID, the result stays Safe.
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Suspicious", "reasons": [
        {"evidence_ids": [payee], "en": "The UPI ID looks like a personal mobile number.", "kn": "x"}],
        "summary_en": "Unusual for a shop."}, "ok", 5))
    result = ex.explain(analysis)
    assert result["verdict"] == "Safe"
    assert result["reasons"] == [] and result["summary_en"] != "Unusual for a shop."


def test_personal_upi_promising_money_is_still_flagged():
    a = analyze_qr("upi://pay?pa=9900112233@paytm&pn=Refund%20Desk&tn=claim%20refund")
    assert any(e["key"] == "qr.personal_handle" for e in a["evidence"])


def test_invalid_json_falls_back_to_rules(fixture, monkeypatch):
    calls = []
    monkeypatch.setattr(ex, "_chat", lambda content: calls.append(1) or "not json at all")
    result = ex.explain(fixture("qr_cashback.json"))
    assert len(calls) == 2  # one retry
    assert result["ai"]["status"] == "invalid_json"
    assert result["verdict"] == "Dangerous"
    assert all(r["source"] == "rules" for r in result["reasons"])


def test_model_unavailable_falls_back(fixture, monkeypatch):
    def boom(content):
        raise ConnectionError("no ollama")
    monkeypatch.setattr(ex, "_chat", boom)
    result = ex.explain(fixture("apk_fake.json"))
    assert result["ai"]["status"] == "unavailable"
    assert result["verdict"] == "Dangerous"


def test_repeat_scan_uses_cache(fixture, monkeypatch):
    calls = []

    def fake(a, s):
        calls.append(1)
        return {"verdict": "Dangerous", "reasons": []}, "ok", 1500

    monkeypatch.setattr(ex, "call_model", fake)
    first = ex.explain(fixture("apk_fake.json"))
    second = ex.explain(fixture("apk_fake.json"))
    assert len(calls) == 1
    assert first["ai"]["cached"] is False and second["ai"]["cached"] is True
    assert second["verdict"] == first["verdict"]


def test_failed_model_answers_are_not_cached(fixture, monkeypatch):
    calls = []
    monkeypatch.setattr(ex, "call_model", lambda a, s: calls.append(1) or (None, "unavailable", 0))
    ex.explain(fixture("apk_fake.json"))
    ex.explain(fixture("apk_fake.json"))
    assert len(calls) == 2


# ------------------------------------------------------------------ real-world QR photos
def _dense_photo_bytes():
    """A dense, PhonePe-style signed QR, shrunk, rotated, blurred and JPEG-compressed."""
    import cv2
    import numpy as np
    import qrcode

    payload = ("upi://pay?ver=01&mode=01&pa=Q123456789@ybl&pn=Sharma%20General%20Store&mc=5411"
               "&tr=STQ123456789012345&mid=M22ABCDEFGHIJ&sign=" + "A1b2C3d4" * 40)
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=4)
    q.add_data(payload)
    img = np.array(q.make_image().convert("RGB"))
    canvas = np.full((2400, 1800, 3), 150, np.uint8)
    small = cv2.resize(img, (700, 700))
    canvas[800:1500, 550:1250] = small
    M = cv2.getRotationMatrix2D((900, 1150), 11, 1.0)
    canvas = cv2.warpAffine(canvas, M, (1800, 2400), borderValue=(150, 150, 150))
    canvas = cv2.GaussianBlur(canvas, (5, 5), 0)
    ok, buf = cv2.imencode(".jpg", canvas, [cv2.IMWRITE_JPEG_QUALITY, 65])
    return buf.tobytes(), payload


def test_decodes_dense_rotated_phone_photo():
    data, payload = _dense_photo_bytes()
    from scripts.analyze_qr import decode_qr_image
    assert decode_qr_image(data) == payload


def test_bharat_qr_is_checked_like_upi():
    def f(tag, val):
        return f"{tag}{len(val):02d}{val}"
    emv = (f("00", "01") + f("01", "11")
           + f("26", f("00", "A000000677010111") + f("01", "sharmastores@okaxis"))
           + f("52", "5411") + f("53", "356") + f("58", "IN") + f("59", "Sharma General Store")
           + f("60", "Bengaluru"))
    a = analyze_qr(emv, "Annapoorna Cafe")
    assert a["meta"]["format"] == "Bharat QR" and a["meta"]["payee_upi"] == "sharmastores@okaxis"
    assert ex.explain(a, use_model=False)["verdict"] == "Suspicious"


# ------------------------------------------------------------------ Windows programs
def _program_bytes(demo_samples):
    return (demo_samples / "PhotoViewer_Setup.exe").read_bytes()  # signed, harmless


@pytest.mark.parametrize("name,key", [
    ("invoice.pdf.exe", "exe.double_extension"),
    ("photo.jpg   .exe", "exe.double_extension"),
    ("statement.pdf", "exe.disguised_extension"),
    ("update.apk", "exe.disguised_extension"),
    ("report\u202efdp.exe", "exe.hidden_name"),
])
def test_disguised_program_names(tmp_path, demo_samples, name, key):
    f = tmp_path / "x.bin"
    f.write_bytes(_program_bytes(demo_samples))
    a = analyze_file(f, name)
    assert a["kind"] == "exe" and any(e["key"] == key for e in a["evidence"])
    assert ex.explain(a, use_model=False)["verdict"] == "Dangerous"


def test_plain_signed_program_is_safe(tmp_path, demo_samples):
    f = tmp_path / "setup.exe"
    f.write_bytes(_program_bytes(demo_samples))
    assert ex.explain(analyze_file(f), use_model=False)["verdict"] == "Safe"


def test_unknown_file_type_is_rejected(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    with pytest.raises(InputError):
        analyze_file(f)


# ------------------------------------------------------------------ language guard
def test_script_check():
    assert ex.script_ok("ಈ ಆಪ್ ನಿಮ್ಮ SMS ಓದಬಲ್ಲದು, OTP ಸೇರಿ ₹500.", "kn")
    assert not ex.script_ok("ಇದು 숨겨진 ಕೋಡ್ ಬಳಸುತ್ತದೆ.", "kn")      # Korean word
    assert not ex.script_ok("यह ऐप खतरनाक है", "kn")                  # Hindi script
    assert not ex.script_ok("This app reads SMS", "kn")               # no Kannada at all
    assert ex.script_ok("It reads your OTPs.", "en")
    assert not ex.script_ok("It uses 隐藏 code.", "en")


def test_wrong_script_from_model_is_replaced(fixture, monkeypatch):
    analysis = fixture("apk_fake.json")
    tele = next(e["id"] for e in analysis["evidence"] if e["key"] == "string.telegram_bot")
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Dangerous", "reasons": [
        {"evidence_ids": [tele], "en": "It sends data to a Telegram bot.",
         "kn": "ಇದು 숨겨진 ಕೋಡ್ ಬಳಸುತ್ತದೆ."}],
        "summary_en": "Do not install.", "summary_kn": "설치하지 마세요."}, "ok", 5))
    result = ex.explain(analysis)
    for r in result["reasons"]:
        assert ex.script_ok(r["kn"], "kn"), r["kn"]
    assert ex.script_ok(result["summary_kn"], "kn")
    assert result["ai"]["fixed_language"] == 2


# ------------------------------------------------------------------ messages
@pytest.mark.parametrize("text,sender", [
    ("Your income tax refund of Rs 15,490 is approved. Claim your refund now: https://bit.ly/demo-not-real", None),
    ("Your bank account will be suspended. Share the OTP sent to your mobile to verify and keep it active.", None),
    ("Congratulations! You have won Rs 25,00,000 in KBC lucky draw. To claim your prize send your bank details on WhatsApp 7019283746.", None),
    ("RTO e-challan of Rs 500 pending. Download the app to pay now: http://203.0.113.9/rto-challan.apk", "VM-ECHLNX"),
])
def test_scam_messages_are_dangerous(text, sender):
    assert ex.explain(analyze_sms(text, sender), use_model=False)["verdict"] == "Dangerous"


@pytest.mark.parametrize("text,sender", [
    ("482913 is your OTP for Rs 1,250.00 at AMAZON on your HDFC Bank card. Do not share this OTP with anyone. -HDFC Bank", "AX-HDFCBK"),
    ("Rs 500.00 debited from A/c XX1234 to VPA sharmastores@okaxis. Not you? Call 18001234 to block. -SBI", "VM-SBIINB-S"),
    ("Your e-challan has been generated. Pay at https://echallan.parivahan.gov.in within 60 days.", "VM-ECHLAN-G"),
    ("Hey, are we still meeting at 6 today? Call me on 9876501234 when you reach.", "+919876501234"),
    ("Your refund of Rs 499 for order 402-1234 has been processed. -Amazon", "AX-AMAZON"),
    ("Your BESCOM bill of Rs 842 is generated. Due 05-11-2026. Pay at bescom.karnataka.gov.in", "VM-BESCOM-S"),
])
def test_genuine_messages_are_safe(text, sender):
    result = ex.explain(analyze_sms(text, sender), use_model=False)
    assert result["verdict"] == "Safe" and result["score"] < 30


def test_lookalike_domain_detected():
    a = analyze_sms("Update KYC at https://sbi-kyc-verify.example/login")
    assert any(e["key"] == "sms.lookalike_domain" for e in a["evidence"])
    b = analyze_sms("Login at https://www.onlinesbi.sbi to view your statement.")
    assert not any(e["key"] == "sms.lookalike_domain" for e in b["evidence"])


def test_empty_message_is_rejected():
    with pytest.raises(InputError):
        analyze_sms("   ")
