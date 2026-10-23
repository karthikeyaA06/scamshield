"""Analyzers, scoring and the model validator."""

import json

import pytest

from scripts import explain as ex
from scripts.analyze_apk import analyze_apk
from scripts.analyze_qr import analyze_qr, analyze_qr_image
from scripts.common import InputError
from scripts.score import score


# ------------------------------------------------------------------ demo samples
@pytest.mark.parametrize("sample_id", ["apk_fake", "apk_safe", "qr_shop", "qr_cashback", "qr_sticker"])
def test_demo_samples_give_expected_verdicts(demo_samples, sample_id):
    meta = json.loads((demo_samples / "samples.json").read_text(encoding="utf-8"))
    sample = next(s for s in meta["samples"] if s["id"] == sample_id)
    path = demo_samples / sample["file"]
    if sample["kind"] == "apk":
        analysis = analyze_apk(path)
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


def test_model_can_raise_the_verdict(fixture, monkeypatch):
    analysis = fixture("apk_safe.json")
    monkeypatch.setattr(ex, "call_model", lambda a, s: ({"verdict": "Suspicious", "reasons": [
        {"evidence_ids": ["E1"], "en": "Odd name.", "kn": "ವಿಚಿತ್ರ ಹೆಸರು."}]}, "ok", 5))
    assert ex.explain(analysis)["verdict"] == "Suspicious"


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
