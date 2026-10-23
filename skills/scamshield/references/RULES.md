# ScamShield rules

Weights live in `../assets/rules.json`. This file explains them. Keep both in sync.

Score = sum of triggered weights, capped at 100.
Verdict floor: **0-29 Safe, 30-59 Suspicious, 60+ Dangerous.**
The model can raise the verdict above the floor but can never lower it.

## APK: permissions

Total permission weight is capped at **45**, so a long list of permissions alone
cannot reach Dangerous. Combinations (below) are what push a scam app over the line.

| Rule | Weight | Why |
|---|---|---|
| `perm.READ_SMS` | 15 | Reads every SMS, including bank OTPs. The core of OTP theft. |
| `perm.RECEIVE_SMS` | 15 | Gets each SMS the moment it arrives, so OTPs can be forwarded instantly. |
| `perm.SEND_SMS` | 12 | Can send SMS, used to spread the scam to contacts or register SIM-bound services. |
| `perm.BIND_ACCESSIBILITY_SERVICE` | 20 | Sees the screen and taps for the user. Lets malware approve payments. |
| `perm.BIND_NOTIFICATION_LISTENER_SERVICE` | 15 | Reads all notifications, another route to OTPs. |
| `perm.SYSTEM_ALERT_WINDOW` | 8 | Draws over other apps, used for fake login screens. |
| `perm.REQUEST_INSTALL_PACKAGES` | 10 | Installs more apps, typical of droppers. |
| `perm.READ_CONTACTS` | 6 | Harvests contacts for further scams. |
| `perm.READ_CALL_LOG` | 8 | Reads call history. |
| `perm.CALL_PHONE` | 5 | Calls without dialling (USSD call forwarding tricks). |
| `perm.QUERY_ALL_PACKAGES` | 4 | Lists installed apps, often to find banking apps to target. |

## APK: code, identity, signing

| Rule | Weight | Why |
|---|---|---|
| `string.telegram_bot` | 25 | A Telegram Bot API URL in the code is a very common exfiltration channel for Indian SMS stealers. |
| `string.raw_ip` | 15 | Connecting to a bare IP address avoids domain takedowns. |
| `string.firebase_db` | 5 | Common in legit apps; low weight, context only. |
| `string.sensitive_keywords` | 5 | Words like otp, upi, kyc, challan, refund in the code. Context only. |
| `impersonation` | 25 | Name looks like a government/bank app (RTO, challan, KYC, PM Kisan, bank names) but the package is not on the official list. |
| `cert.debug` | 10 | Signed with the Android debug certificate. Real publishers never ship this. |
| `cert.unsigned` | 15 | No signature at all, nobody can be identified. |
| `code.packer` | 20 | A known packer (Jiagu, Bangcle, Legu, ...) hides the real code. |
| `code.no_dex` | 15 | No normal app code present; it may be loaded later from elsewhere. |

## APK: combinations

| Rule | Weight | Triggered when |
|---|---|---|
| `combo.otp_theft` | 25 | SMS read/receive **and** an exfiltration channel (Telegram bot or raw IP). |
| `combo.screen_takeover` | 15 | Accessibility **and** SMS, overlay or notification access. |
| `combo.fake_official_sms` | 15 | Impersonation **and** any SMS permission. |

## UPI QR codes

| Rule | Weight | Why |
|---|---|---|
| `qr.web_link` | 20 | The QR opens a website instead of a payment: possible phishing. |
| `qr.prefilled_amount` | 20 | Amount already set. Normal at a billing counter, risky anywhere else. |
| `qr.receive_wording` | 45 | Note or name promises money (receive, refund, cashback, prize, KYC). Scanning a QR can never receive money. |
| `qr.personal_handle` | 15 | Payee is a 10-digit mobile number handle while presented as a shop or a refund. |
| `qr.name_mismatch` | 30 | Name in the QR differs from the shop the user says they are paying. Generic words like "store" are ignored when comparing. |
| `qr.registry_mismatch` | 35 | The UPI ID's registered name differs from the name in the QR. **Demo uses mock data.** |
| `combo.fake_receive` | 25 | Pre-filled amount **and** receive-money wording: the classic "scan to receive" scam. |

## Changing the rules

1. Edit the weight in `assets/rules.json`.
2. Update this table.
3. Run `pytest` from the repo root; the demo-sample tests check the expected verdicts.
