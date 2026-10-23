# ScamShield rules

Weights live in `../assets/rules.json`. This file explains them. Keep both in sync.

Score = sum of triggered weights, capped at 100.
Verdict floor: **0-29 Safe, 30-59 Suspicious, 60+ Dangerous.**
The model can raise the verdict above the floor but can never lower it, and it can only raise it
when its reasons cite real risk evidence (severity low, medium or high), not just context.

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

## Windows programs (.exe)

The file type is read from the file's first bytes ("MZ"), not its name, so a program
renamed to `.pdf` or `.apk` is still recognised.

| Rule | Weight | Why |
|---|---|---|
| `exe.windows_program` | 20 | Any program received from someone is a risk; on its own this stays Safe. |
| `exe.double_extension` | 45 | Name like `receipt.pdf.exe`: a program pretending to be a document. |
| `exe.disguised_extension` | 45 | A program whose name ends in `.pdf`, `.apk`, `.jpg` and so on. |
| `exe.hidden_name` | 45 | Right-to-left override character used to flip the visible extension. |
| `exe.keylogger_api` | 20 | `GetAsyncKeyState` / `SetWindowsHookEx`: can record every key pressed. |
| `exe.packer` | 15 | UPX, ASPack, Themida, VMProtect and similar sections hide the real code. |
| `exe.unsigned` | 15 | No Authenticode signature block. (Presence only; not verified offline.) |
| `combo.keylogger_exfil` | 25 | Keylogger functions **and** a Telegram bot or raw IP link: password theft. |

`string.telegram_bot`, `string.raw_ip`, `string.sensitive_keywords` and `impersonation`
apply to programs too.

## Messages (SMS / WhatsApp)

The text is only read. Links are never opened. A genuine bank OTP that says "do not share"
does not count as asking for a secret. Official sites come from `assets/official_domains.json`.

| Rule | Weight | Why |
|---|---|---|
| `sms.lookalike_domain` | 35 | Link uses a brand name (SBI, RTO, Aadhaar...) on a domain that isn't the brand's own. |
| `sms.short_link` | 20 | bit.ly and similar hide the real destination. |
| `sms.apk_link` | 45 | A link to an `.apk` file. Banks and government never send apps by message. |
| `sms.chat_link` | 10 | Moves you to a private WhatsApp/Telegram chat. |
| `sms.urgency` | 15 | "immediately", "blocked", "disconnected", "within 24 hours"... |
| `sms.asks_secret` | 35 | Asks you to share OTP, PIN, CVV, password or bank details. |
| `sms.money_lure` | 25 | "won", "lottery", "claim your", "lucky draw"... (plain "refund" is not counted). |
| `sms.kyc_update` | 20 | Account blocked unless you update KYC/PAN. |
| `sms.job_scam` | 30 | Part-time / work-from-home easy money, liking videos, tasks. |
| `sms.authority_threat` | 30 | Police, CBI, customs, drugs parcel, arrest warrant. |
| `sms.power_cut` | 30 | Electricity will be disconnected. |
| `sms.call_number` | 10 | Asks you to call a personal mobile number (only when the message claims an organisation or promises money). |
| `sms.personal_sender` | 25 | Claims to be an organisation but sent from a personal 10-digit number. |
| `combo.sms_phish` | 25 | Suspicious link **and** pressure or a money promise. |
| `combo.sms_secret_grab` | 20 | Asks for secrets **and** pressure. |
| `combo.digital_arrest` | 25 | Threats from "officials" **and** urgency. |
| `combo.task_scam` | 25 | Job offer **and** a private chat, money lure or personal sender. |

## UPI QR codes

| Rule | Weight | Why |
|---|---|---|
| `qr.web_link` | 20 | The QR opens a website instead of a payment: possible phishing. |
| `qr.prefilled_amount` | 20 | Amount already set. Normal at a billing counter, risky anywhere else. |
| `qr.receive_wording` | 45 | Note or name promises money (receive, refund, cashback, prize, KYC). Scanning a QR can never receive money. |
| `qr.personal_handle` | 15 | Payee is a 10-digit mobile number handle **and** the QR promises money (refund, cashback). A mobile-number UPI ID on its own is normal: many genuine small shops and people use one. |
| `qr.name_mismatch` | 30 | Name in the QR differs from the shop the user says they are paying. Generic words like "store" are ignored when comparing. |
| `qr.registry_mismatch` | 35 | The UPI ID's registered name differs from the name in the QR. **Demo uses mock data.** |
| `combo.fake_receive` | 25 | Pre-filled amount **and** receive-money wording: the classic "scan to receive" scam. |

## Changing the rules

1. Edit the weight in `assets/rules.json`.
2. Update this table.
3. Run `pytest` from the repo root; the demo-sample tests check the expected verdicts.
