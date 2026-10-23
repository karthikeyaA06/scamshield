"""A stand-in for Ollama, used ONLY by tests (and for UI work on machines without Gemma).

It answers /api/tags and /api/chat. The chat reply is built from the evidence it is
sent, and it deliberately includes one reason citing a non-existent evidence ID so
the validator in explain.py can be seen removing it. Set FAKE_VERDICT to force a
verdict (for example "Safe", to prove the rules stop the model lowering risk).

Run:  uvicorn tests.fake_ollama:app --port 11434
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request

app = FastAPI()

TEXT = {
    "combo.otp_theft": ("It reads your OTP messages and sends them to a Telegram bot run by the scammer.",
                        "ಇದು ನಿಮ್ಮ OTP ಸಂದೇಶಗಳನ್ನು ಓದಿ ವಂಚಕರ ಟೆಲಿಗ್ರಾಮ್ ಬಾಟ್‌ಗೆ ಕಳುಹಿಸುತ್ತದೆ."),
    "impersonation": ("It pretends to be an official traffic challan app, but it is not.",
                      "ಇದು ಅಧಿಕೃತ ಟ್ರಾಫಿಕ್ ಚಲನ್ ಆಪ್‌ನಂತೆ ನಟಿಸುತ್ತದೆ, ಆದರೆ ಅದು ನಿಜವಲ್ಲ."),
    "combo.screen_takeover": ("It can watch your screen and press buttons, so it could approve payments for you.",
                              "ಇದು ನಿಮ್ಮ ಪರದೆಯನ್ನು ನೋಡಿ ಬಟನ್ ಒತ್ತಬಲ್ಲದು, ಆದ್ದರಿಂದ ನಿಮ್ಮ ಪರವಾಗಿ ಪಾವತಿ ಮಾಡಬಲ್ಲದು."),
    "qr.receive_wording": ("It promises cashback, but scanning a QR only ever sends money.",
                           "ಇದು ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್ ಭರವಸೆ ನೀಡುತ್ತದೆ, ಆದರೆ QR ಸ್ಕ್ಯಾನ್ ಮಾಡಿದರೆ ಹಣ ಹೋಗುತ್ತದೆ ಮಾತ್ರ."),
    "combo.fake_receive": ("₹{amount} is already filled in, so you would pay that amount, not receive it.",
                           "₹{amount} ಮೊದಲೇ ತುಂಬಲಾಗಿದೆ, ಆದ್ದರಿಂದ ನೀವು ಆ ಹಣ ಪಾವತಿಸುತ್ತೀರಿ, ಪಡೆಯುವುದಿಲ್ಲ."),
    "qr.name_mismatch": ("The QR pays a different shop from the one you are standing in.",
                         "ಈ QR ನೀವು ಇರುವ ಅಂಗಡಿಗಲ್ಲ, ಬೇರೆ ಅಂಗಡಿಗೆ ಹಣ ಕಳುಹಿಸುತ್ತದೆ."),
}


@app.get("/api/tags")
def tags():
    return {"models": [{"name": "gemma4:e4b"}]}


@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    payload = json.loads(body["messages"][-1]["content"].split("\n\nYour last reply")[0])
    reasons = []
    for hit in payload["rules_triggered"]:
        if hit["rule"] in TEXT and len(reasons) < 3:
            amount = payload.get("details", {}).get("amount", "")
            en, kn = (x.replace("{amount}", amount) for x in TEXT[hit["rule"]])
            reasons.append({"evidence_ids": hit["evidence_ids"], "en": en, "kn": kn})
    if payload["rules_triggered"]:
        reasons.append({"evidence_ids": ["E99"], "en": "It also records your calls.", "kn": "ಇದು ಕರೆಗಳನ್ನು ದಾಖಲಿಸುತ್ತದೆ."})
    verdict = os.environ.get("FAKE_VERDICT") or payload["rule_verdict"]
    reply = {
        "verdict": verdict,
        "reasons": reasons,
        "summary_en": {"Dangerous": "This is a scam. Do not install or pay.",
                       "Suspicious": "Something is off here. Check before you continue.",
                       "Safe": "Nothing here looks like a scam."}[verdict],
        "summary_kn": {"Dangerous": "ಇದು ವಂಚನೆ. ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಪಾವತಿಸಬೇಡಿ.",
                       "Suspicious": "ಇಲ್ಲಿ ಏನೋ ಸರಿಯಿಲ್ಲ. ಮುಂದುವರಿಯುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ.",
                       "Safe": "ಇಲ್ಲಿ ವಂಚನೆಯಂತೆ ಏನೂ ಕಾಣುತ್ತಿಲ್ಲ."}[verdict],
    }
    return {"message": {"role": "assistant", "content": json.dumps(reply, ensure_ascii=False)}}
