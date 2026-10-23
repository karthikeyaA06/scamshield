"""Evidence + rule score -> Gemma (local, via Ollama) -> validated verdict.

The model's job is to reason over the COMBINATION of evidence and explain it in
plain English and Kannada. Three guardrails keep it honest:
  1. It only sees extracted evidence, and must cite evidence IDs for every reason.
  2. A validator drops any reason that cites an ID that does not exist.
  3. The final verdict is the more severe of (model verdict, rule floor), so the
     model can raise the risk level but can never talk it down.
If Ollama is not running or the model returns invalid JSON twice, ScamShield
falls back to rule-based template explanations, so the tool never crashes.

Usage:
    python explain.py evidence.json [--no-model]
"""

from __future__ import annotations

import argparse
import json
import os
import string
import sys
import time

try:
    from .common import DISCLAIMER, load_asset
    from .score import VERDICTS, more_severe, score as rule_score
except ImportError:  # pragma: no cover
    from common import DISCLAIMER, load_asset
    from score import VERDICTS, more_severe, score as rule_score

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("SCAMSHIELD_MODEL", "gemma4:e4b")
TIMEOUT_S = float(os.environ.get("SCAMSHIELD_TIMEOUT", "120"))
MAX_REASONS = 4

SYSTEM_PROMPT = """You are ScamShield, a cautious security explainer for ordinary people in India who are not technical. You receive evidence that was extracted automatically from an Android app file or a UPI QR code, plus a rule-based risk score.

Your job:
1. Combine the evidence to work out what the app or QR code would actually do to the user. Look for combinations. Examples: reads SMS + sends data to a Telegram bot = steals OTPs. Screen control + SMS access = can move money without the user knowing. Amount already filled in + "receive money" text = the user would PAY, not receive.
2. Give a verdict: "Safe", "Suspicious" or "Dangerous".
3. Explain each reason in one short, simple English sentence, and give the same meaning in simple Kannada.

Rules:
- Use ONLY the evidence given. Never invent permissions, links, names or amounts.
- Every reason must cite the evidence IDs it is based on, like "E3".
- Say what the app or QR can DO to the user. Avoid technical words like permission, APK, manifest, payload.
- At most 4 reasons, most serious first. Short sentences.
- Reply with JSON only, exactly in this shape:
{"verdict": "Safe|Suspicious|Dangerous", "reasons": [{"evidence_ids": ["E1"], "en": "...", "kn": "..."}], "summary_en": "...", "summary_kn": "..."}"""


class _SafeDict(dict):
    def __missing__(self, key):  # leave unknown placeholders readable
        return "{" + key + "}"


def _fmt(template: str, params: dict) -> str:
    return string.Formatter().vformat(template, (), _SafeDict(params))


# ---------------------------------------------------------------- model access
def model_status(timeout: float = 1.5) -> dict:
    """Is Ollama reachable, and is the configured model pulled?"""
    import requests

    status = {"host": OLLAMA_HOST, "model": MODEL, "reachable": False, "installed": False}
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=timeout)
        resp.raise_for_status()
        names = [m.get("name", "") for m in resp.json().get("models", [])]
        status["reachable"] = True
        wanted = {MODEL, MODEL + ":latest"}
        if MODEL in ("gemma4:e4b", "gemma4"):
            wanted |= {"gemma4:latest", "gemma4", "gemma4:e4b"}
        status["installed"] = any(n in wanted for n in names)
    except Exception:
        pass
    return status


def _model_input(analysis: dict, scoring: dict) -> str:
    evidence = [{k: item[k] for k in ("id", "type", "value", "label", "severity")}
                for item in analysis["evidence"]]
    meta = {k: v for k, v in analysis.get("meta", {}).items()
            if k in ("package", "label", "type", "payee_upi", "payee_name", "amount", "note", "shop_name")}
    payload = {
        "checking": "Android app file" if analysis["kind"] == "apk" else "UPI QR code",
        "details": meta,
        "evidence": evidence,
        "rule_score": scoring["score"],
        "rule_verdict": scoring["floor"],
        "rules_triggered": [{"rule": h["rule"], "evidence_ids": h["evidence_ids"]} for h in scoring["hits"]],
    }
    return json.dumps(payload, ensure_ascii=False)


def _chat(user_content: str) -> str:
    import requests

    body = {
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user_content}],
        "stream": False,
        "format": "json",
        "think": False,
        "options": {"temperature": 0, "num_ctx": 8192},
    }
    resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=body, timeout=TIMEOUT_S)
    if resp.status_code == 400 and "think" in resp.text.lower():
        body.pop("think")  # older Ollama builds or models without a thinking switch
        resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=body, timeout=TIMEOUT_S)
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def call_model(analysis: dict, scoring: dict) -> tuple[dict | None, str, int]:
    """Return (parsed_json_or_None, status, latency_ms). Retries once on invalid JSON."""
    start = time.monotonic()
    user_content = _model_input(analysis, scoring)
    for attempt in range(2):
        try:
            raw = _chat(user_content)
        except Exception:
            return None, "unavailable", int((time.monotonic() - start) * 1000)
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed, "ok", int((time.monotonic() - start) * 1000)
        except json.JSONDecodeError:
            pass
        user_content += "\n\nYour last reply was not valid JSON. Reply with the JSON object only."
    return None, "invalid_json", int((time.monotonic() - start) * 1000)


# ------------------------------------------------------------ rule templates
def _params_for(ids: list[str], analysis: dict) -> dict:
    params: dict = {}
    by_id = {e["id"]: e for e in analysis["evidence"]}
    for i in ids:
        params.update(by_id.get(i, {}).get("params", {}))
    return params


def template_reasons(analysis: dict, scoring: dict) -> list[dict]:
    """Rule-based reasons, strongest first. A single-permission reason is skipped when a
    combination reason already explains that permission, so reasons don't repeat."""
    texts = load_asset("explanations.json")["rules"]
    combo_ids = {i for h in scoring["hits"] if h["combo"] for i in h["evidence_ids"]}
    reasons = []
    for hit in scoring["hits"]:
        t = texts.get(hit["rule"])
        if not t:
            continue
        if hit["rule"].startswith("perm.") and set(hit["evidence_ids"]) <= combo_ids:
            continue
        params = _params_for(hit["evidence_ids"], analysis)
        reasons.append({"evidence_ids": hit["evidence_ids"], "en": _fmt(t["en"], params),
                        "kn": _fmt(t["kn"], params), "source": "rules", "rule": hit["rule"]})
    return reasons


def _normalise_verdict(value) -> str | None:
    if not isinstance(value, str):
        return None
    for v in VERDICTS:
        if value.strip().lower() == v.lower():
            return v
    return None


# ---------------------------------------------------------------- validator
def validate(model_out: dict, analysis: dict, scoring: dict) -> dict:
    valid_ids = {e["id"] for e in analysis["evidence"]}
    templates = template_reasons(analysis, scoring)
    tmpl_by_ids = {tuple(sorted(t["evidence_ids"])): t for t in templates}

    dropped = 0
    reasons = []
    for r in (model_out.get("reasons") or [])[: MAX_REASONS + 2]:
        if not isinstance(r, dict):
            dropped += 1
            continue
        cited = [i for i in (r.get("evidence_ids") or []) if isinstance(i, str) and i in valid_ids]
        en = (r.get("en") or "").strip()
        if not cited or not en:
            dropped += 1
            continue
        kn = (r.get("kn") or "").strip()
        if not kn:
            match = tmpl_by_ids.get(tuple(sorted(cited)))
            kn = match["kn"] if match else en
        reasons.append({"evidence_ids": cited, "en": en[:300], "kn": kn[:400], "source": "model"})
    reasons = reasons[:MAX_REASONS]

    # If the model missed every serious rule, add the strongest rule reasons back.
    cited_all = {i for r in reasons for i in r["evidence_ids"]}
    supplemented = 0
    for t in templates:
        if len(reasons) >= MAX_REASONS:
            break
        if not cited_all & set(t["evidence_ids"]):
            reasons.append(t)
            cited_all |= set(t["evidence_ids"])
            supplemented += 1

    model_verdict = _normalise_verdict(model_out.get("verdict"))
    final = more_severe(model_verdict or scoring["floor"], scoring["floor"])
    return {
        "model_verdict": model_verdict,
        "final": final,
        "reasons": reasons,
        "summary_en": (model_out.get("summary_en") or "").strip()[:300],
        "summary_kn": (model_out.get("summary_kn") or "").strip()[:400],
        "dropped_reasons": dropped,
        "supplemented_reasons": supplemented,
    }


# ---------------------------------------------------------------- entry point
def explain(analysis: dict, scoring: dict | None = None, use_model: bool = True) -> dict:
    scoring = scoring or rule_score(analysis)
    texts = load_asset("explanations.json")
    kind = analysis["kind"]

    ai = {"model": MODEL, "used": False, "status": "skipped", "latency_ms": 0,
          "model_verdict": None, "raised_by_rules": False, "dropped_reasons": 0,
          "supplemented_reasons": 0}
    model_out, status, latency = (None, "skipped", 0)
    if use_model:
        model_out, status, latency = call_model(analysis, scoring)
    ai.update(status=status, latency_ms=latency)

    if model_out is not None:
        v = validate(model_out, analysis, scoring)
        verdict = v["final"]
        reasons = v["reasons"]
        ai.update(used=True, model_verdict=v["model_verdict"],
                  raised_by_rules=(v["model_verdict"] is not None and v["model_verdict"] != verdict),
                  dropped_reasons=v["dropped_reasons"], supplemented_reasons=v["supplemented_reasons"])
        summary = texts["summaries"][kind][verdict]
        # Keep the model's own summary only when it agrees with the final verdict.
        if v["summary_en"] and not ai["raised_by_rules"]:
            summary = {"en": v["summary_en"], "kn": v["summary_kn"] or summary["kn"]}
    else:
        verdict = scoring["floor"]
        reasons = template_reasons(analysis, scoring)[:MAX_REASONS + 1]
        summary = texts["summaries"][kind][verdict]

    # Next steps are fixed text on purpose: safety advice must never depend on the model.
    steps = texts["next_steps"][kind][verdict]
    return {
        "kind": kind,
        "verdict": verdict,
        "score": scoring["score"],
        "rule_floor": scoring["floor"],
        "thresholds": scoring["thresholds"],
        "hits": scoring["hits"],
        "summary_en": summary["en"],
        "summary_kn": summary["kn"],
        "reasons": reasons,
        "next_steps_en": [s["en"] for s in steps],
        "next_steps_kn": [s["kn"] for s in steps],
        "disclaimer": DISCLAIMER,
        "ai": ai,
        "meta": analysis.get("meta", {}),
        "evidence": analysis["evidence"],
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Explain evidence with the local model.")
    ap.add_argument("evidence", help="JSON output of analyze_apk.py or analyze_qr.py")
    ap.add_argument("--no-model", action="store_true", help="Use rule templates only")
    args = ap.parse_args()
    with open(args.evidence, encoding="utf-8") as fh:
        data = json.load(fh)
    print(json.dumps(explain(data, use_model=not args.no_model), indent=2, ensure_ascii=False))
