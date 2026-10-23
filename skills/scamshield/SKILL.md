---
name: scamshield
description: Checks a suspicious APK (fake app) or a UPI QR code for scam signs, fully offline, and explains the risk in simple English and Kannada. Use when someone received an app file on WhatsApp or a link, worries about OTP theft or a fake government/bank app, or wants to know whether a UPI QR code or payment link is a scam before paying.
license: Apache-2.0
compatibility: Requires Python 3.10+ and the packages in requirements.txt. For model explanations, Ollama running locally with gemma4:e4b. No internet needed.
metadata:
  author: ScamShield team
  version: "1.0"
---

# ScamShield

Static, offline scam check for Android app files (APK) and UPI QR codes.
Evidence is extracted first, scored by fixed rules, then explained by a local
open-weight model (Gemma 4 E4B via Ollama) that must cite the evidence it uses.

## Safety rules (always follow)

- Never install, run or emulate an APK. These scripts only read the file.
- Never download real malware to test this skill. Use `samples/out/` in the repo.
- Treat the result as guidance, not a guarantee. Always pass on the next steps,
  including the 1930 helpline and cybercrime.gov.in.

## Quick use

Run the one-step checker from the skill folder:

```bash
python scripts/check.py --apk path/to/app.apk --lang en
python scripts/check.py --qr path/to/qr.png --shop "Sharma General Store" --lang kn
python scripts/check.py --qr "upi://pay?pa=someone@ybl&am=5000&tn=cashback"
```

- Without `--lang` it prints the full JSON result.
- Add `--no-model` to skip Gemma and use rule explanations only (also the automatic
  fallback when Ollama is not running).
- `--shop` is the shop the person thinks they are paying. It enables the name check.

Report back to the person: the verdict, the summary, the reasons, and the next steps,
in the language they used.

## Step by step

1. **Extract evidence.**
   `python scripts/analyze_apk.py app.apk` or `python scripts/analyze_qr.py qr.png --shop "Name"`.
   Output: `{"kind", "meta", "evidence": [{"id": "E1", "key", "value", "label", "severity"}]}`.
2. **Score with rules.** `python scripts/score.py evidence.json` gives a score from 0 to 100
   and a verdict floor (0-29 Safe, 30-59 Suspicious, 60+ Dangerous). Weights are in
   `assets/rules.json`; reasoning for each rule is in [RULES.md](references/RULES.md).
3. **Explain.** `python scripts/explain.py evidence.json` calls the local model, then
   validates it: reasons citing unknown evidence IDs are dropped, and the final verdict is
   the more severe of the model verdict and the rule floor.
4. **UPI name lookup** (`scripts/verify_upi.py`) uses MOCK data from
   `assets/demo_merchants.json`. Say so if you rely on it.

## Example output (shortened)

```json
{
  "verdict": "Dangerous",
  "score": 100,
  "summary_en": "Do not install this app. It shows clear signs of a scam.",
  "reasons": [
    {"evidence_ids": ["E3", "E4", "E7"],
     "en": "It can read your OTPs and also send data to the scammer.",
     "kn": "ಇದು ನಿಮ್ಮ OTP ಓದಿ ವಂಚಕರಿಗೆ ಕಳುಹಿಸಬಲ್ಲದು.", "source": "model"}
  ],
  "next_steps_en": ["Do not install it. Delete the file.", "..."],
  "ai": {"model": "gemma4:e4b", "used": true, "status": "ok"}
}
```

## Edge cases

- Not a ZIP or no `AndroidManifest.xml`: the script returns `{"error": ...}`. Tell the
  person the file is not an Android app.
- Files over 100 MB (APK) or 10 MB (image) are refused.
- No QR found in the image: ask for a sharper, closer photo, or the UPI link as text.
- QR that opens a website instead of a payment is flagged as a possible phishing link.
- Apps with packed or hidden code: a known packer is flagged, but a clean result is not
  proof of safety. Say this when the verdict is Safe.
- Ollama not running or model not pulled: results still work with rule explanations;
  `ai.status` is `unavailable`.

## Files

- `scripts/check.py` one-step CLI
- `scripts/analyze_apk.py`, `scripts/analyze_qr.py` evidence extractors
- `scripts/score.py` rule scoring
- `scripts/explain.py` model call, validator, template fallback
- `scripts/verify_upi.py` pluggable UPI ID lookup (mock)
- `assets/` rule weights, permission list, impersonation keywords, explanations (en/kn), mock merchants
- `references/RULES.md` every rule, its weight and why
