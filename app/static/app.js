/* ScamShield frontend. No framework, no network calls except to this server. */
(() => {
  "use strict";

  // ------------------------------------------------------------------ strings
  const T = {
    en: {
      tab_sms: "Message",
      sms_label: "Paste the SMS or WhatsApp message",
      sms_placeholder: "Dear customer, your account will be blocked today…",
      sender_label: "Sender (optional)",
      sender_placeholder: "e.g. AX-HDFCBK or +91 98…",
      sms_hint: "Links in the message are never opened.",
      check_sms: "Check this message",
      msg_from: "From",
      msg_unknown_sender: "Sender not given",
      util_tagline: "Open-source, offline scam checker",
      util_helpline: "Cyber fraud helpline",
      nav_check: "Check",
      nav_how: "How it works",
      nav_limits: "Limits",
      console_title: "New check",
      console_offline: "Runs on this device",
      working_title: "Inspecting",
      report_title: "Inspection report",
      report_id: "Check ID",
      report_time: "Checked",
      report_where: "Where",
      report_device: "Offline, on this device",
      print: "Print or save as PDF",
      footer_independent: "ScamShield is an independent open-source project, not a government service.",
      status_checking: "Checking the local model",
      status_ready: "{model} is ready on this laptop",
      status_missing: "Ollama is running, but {model} isn't pulled. Using rule explanations.",
      status_off: "Model not running. Using rule explanations.",
      status_disabled: "Model turned off. Using rule explanations.",
      headline: "Check before you trust.",
      lede: "Got an app, a program, a payment QR or a message you're not sure about? ScamShield checks it right here on this computer and tells you what it would really do.",
      promise_offline: "Works offline. Nothing is uploaded to the internet.",
      promise_never_runs: "Never installs or runs the file.",
      promise_lang: "Explains in English and Kannada.",
      tab_apk: "App or program",
      tab_qr: "Payment QR",
      drop_apk: "Drop the app or program file here",
      drop_qr: "Drop a photo or screenshot of the QR",
      drop_or: "or",
      drop_choose: "choose a file",
      drop_apk_hint: "Android .apk or Windows .exe, up to 100 MB",
      drop_qr_hint: "PNG or JPG up to 10 MB",
      clear_file: "Remove",
      link_label: "Or paste a UPI link",
      shop_label: "Shop you think you're paying (optional)",
      check_apk: "Check this file",
      win_program: "Windows program",
      check_qr: "Check this QR",
      samples_title: "No file handy? Try a demo sample.",
      sample_go: "Check",
      working: "Reading the file, scoring it, and asking Gemma to explain…",
      err_network: "ScamShield's server isn't responding. Make sure it's running, then try again.",
      err_apk_type: "Choose an .apk file.",
      err_img_type: "Choose a PNG or JPG image of the QR.",
      verdict_Safe: "Safe",
      verdict_Suspicious: "Suspicious",
      verdict_Dangerous: "Dangerous",
      pays: "Money goes to",
      expect_shop: "You expect",
      opens: "Opens",
      text_qr: "Text",
      risk_score: "Risk score",
      why_h: "Why",
      none_found: "No warning signs were found in this check.",
      by_model: "Explained by Gemma",
      by_rules: "Rule explanation",
      show_ev: "Evidence {id}",
      actions_h: "What to do now",
      call: "Call 1930",
      helpline_sub: "National cyber fraud helpline",
      report_online: "Report at cybercrime.gov.in",
      trail_h: "How ScamShield decided",
      t1: "Evidence found",
      t1_v: "{n} items",
      t1_n: "{k} of them raise the risk.",
      t1_n_one: "1 of them raises the risk.",
      t1_n_none: "None of them raise the risk.",
      t2: "Rule score",
      t2_n: "The rules say at least {floor}.",
      t3: "Gemma's reading",
      t3_off: "Not used",
      t3_ok: "Answered in {s} s on this laptop.",
      t3_cached: "Same file checked before, so Gemma's answer was reused instantly.",
      t3_dropped: "Removed {d} reason that cited no real evidence.",
      t3_lang: "Replaced {n} sentence that wasn't in the right language.",
      t3_unavailable: "The model isn't running, so fixed rule explanations were used.",
      t3_invalid: "The model's reply was invalid twice, so rule explanations were used.",
      t4: "Final verdict",
      t4_raised: "Gemma said {mv}, but the rules require at least {floor}.",
      t4_model_higher: "Gemma raised it above the rule score, citing real risk evidence.",
      t4_capped: "Gemma said {mv}, but cited no real risk evidence, so the rules kept it {final}.",
      t4_agree: "Gemma and the rules agree.",
      t4_rules: "Set by the rules.",
      ev_all: "See all evidence ({n})",
      ev_id: "ID",
      ev_what: "What it is",
      ev_found: "Found",
      again: "Check something else",
      why_title: "Why this matters",
      why_statement: "In 2025, people in India reported losing ₹19,813 crore to cyber fraud. Karnataka alone lost ₹2,413 crore, the second highest of any state.",
      why_note: "Fake app files and fake payment QR codes need no skill from the scammer, and most of the money is never recovered. Checking before installing or paying is what saves it.",
      why_source: "Source: I4C data, via IANS",
      how_title: "How a check works",
      how1_t: "Read, never run",
      how1_p: "ScamShield opens the APK as a ZIP archive and reads its permissions, signing certificate and code strings. For a QR code it decodes the payment link. Nothing is installed or executed.",
      how2_t: "Score with open rules",
      how2_p: "Every finding becomes numbered evidence. Published rules give it a score from 0 to 100, with extra weight for dangerous combinations like reading SMS plus a Telegram bot link.",
      how3_t: "Gemma explains, rules guard",
      how3_p: "Gemma 4 E4B, an open-weight model running on this laptop, works out what the combination means and explains it simply. Each reason must cite real evidence, and the model can raise the risk level but never lower it.",
      limits_title: "What ScamShield can't do yet",
      limit1: "Apps that hide their code with advanced packing can slip past a static check. ScamShield flags known packers, but it is a first line of defence, not an antivirus.",
      limit2: "The real owner of a UPI ID is only known to banks. The name lookup here uses demo data, so always read the name your payment app shows before entering your PIN.",
      limit3: "Kannada explanations come from a small model and fixed templates. They are clear, but a native speaker should review them before wider use.",
      footer_license: "Open source under the Apache-2.0 license.",
      footer_model: "Explanations by Gemma 4 E4B through Ollama, running locally.",
      footer_help: "Lost money to fraud? Call",
      footer_or: "or report at",
      footer_repo: "Source code on GitHub",
    },
    kn: {
      tab_sms: "ಸಂದೇಶ",
      sms_label: "SMS ಅಥವಾ WhatsApp ಸಂದೇಶವನ್ನು ಅಂಟಿಸಿ",
      sms_placeholder: "ಉದಾ: ನಿಮ್ಮ ಖಾತೆ ಇಂದು ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ…",
      sender_label: "ಕಳುಹಿಸಿದವರು (ಐಚ್ಛಿಕ)",
      sender_placeholder: "ಉದಾ: AX-HDFCBK ಅಥವಾ +91 98…",
      sms_hint: "ಸಂದೇಶದಲ್ಲಿರುವ ಲಿಂಕ್‌ಗಳನ್ನು ಎಂದಿಗೂ ತೆರೆಯುವುದಿಲ್ಲ.",
      check_sms: "ಈ ಸಂದೇಶ ಪರಿಶೀಲಿಸಿ",
      msg_from: "ಕಳುಹಿಸಿದವರು",
      msg_unknown_sender: "ಕಳುಹಿಸಿದವರ ವಿವರ ನೀಡಿಲ್ಲ",
      util_tagline: "ಮುಕ್ತ ಮೂಲ, ಆಫ್‌ಲೈನ್ ವಂಚನೆ ಪರಿಶೀಲಕ",
      util_helpline: "ಸೈಬರ್ ವಂಚನೆ ಸಹಾಯವಾಣಿ",
      nav_check: "ಪರಿಶೀಲಿಸಿ",
      nav_how: "ಹೇಗೆ ಕೆಲಸ ಮಾಡುತ್ತದೆ",
      nav_limits: "ಮಿತಿಗಳು",
      console_title: "ಹೊಸ ಪರಿಶೀಲನೆ",
      console_offline: "ಈ ಸಾಧನದಲ್ಲೇ ಚಲಿಸುತ್ತದೆ",
      working_title: "ಪರಿಶೀಲಿಸಲಾಗುತ್ತಿದೆ",
      report_title: "ಪರಿಶೀಲನಾ ವರದಿ",
      report_id: "ಪರಿಶೀಲನಾ ID",
      report_time: "ಪರಿಶೀಲಿಸಿದ ಸಮಯ",
      report_where: "ಎಲ್ಲಿ",
      report_device: "ಆಫ್‌ಲೈನ್, ಈ ಸಾಧನದಲ್ಲೇ",
      print: "ಮುದ್ರಿಸಿ ಅಥವಾ PDF ಆಗಿ ಉಳಿಸಿ",
      footer_independent: "ScamShield ಒಂದು ಸ್ವತಂತ್ರ ಮುಕ್ತ ಮೂಲ ಯೋಜನೆ, ಸರ್ಕಾರಿ ಸೇವೆಯಲ್ಲ.",
      status_checking: "ಸ್ಥಳೀಯ ಮಾಡೆಲ್ ಪರಿಶೀಲಿಸಲಾಗುತ್ತಿದೆ",
      status_ready: "{model} ಈ ಲ್ಯಾಪ್‌ಟಾಪ್‌ನಲ್ಲಿ ಸಿದ್ಧವಾಗಿದೆ",
      status_missing: "Ollama ಚಾಲನೆಯಲ್ಲಿದೆ, ಆದರೆ {model} ಡೌನ್‌ಲೋಡ್ ಆಗಿಲ್ಲ. ನಿಯಮ ಆಧಾರಿತ ವಿವರಣೆ ಬಳಸಲಾಗುತ್ತಿದೆ.",
      status_off: "ಮಾಡೆಲ್ ಚಾಲನೆಯಲ್ಲಿಲ್ಲ. ನಿಯಮ ಆಧಾರಿತ ವಿವರಣೆ ಬಳಸಲಾಗುತ್ತಿದೆ.",
      status_disabled: "ಮಾಡೆಲ್ ಆಫ್ ಮಾಡಲಾಗಿದೆ. ನಿಯಮ ಆಧಾರಿತ ವಿವರಣೆ ಬಳಸಲಾಗುತ್ತಿದೆ.",
      headline: "ನಂಬುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ.",
      lede: "ಅನುಮಾನಾಸ್ಪದ ಆಪ್, ಪ್ರೋಗ್ರಾಂ, ಪಾವತಿ QR ಅಥವಾ ಸಂದೇಶ ಬಂದಿದೆಯೇ? ScamShield ಅದನ್ನು ಇದೇ ಕಂಪ್ಯೂಟರ್‌ನಲ್ಲಿ ಪರಿಶೀಲಿಸಿ, ಅದು ನಿಜವಾಗಿ ಏನು ಮಾಡುತ್ತದೆ ಎಂದು ತಿಳಿಸುತ್ತದೆ.",
      promise_offline: "ಆಫ್‌ಲೈನ್‌ನಲ್ಲಿ ಕೆಲಸ ಮಾಡುತ್ತದೆ. ಏನನ್ನೂ ಇಂಟರ್ನೆಟ್‌ಗೆ ಕಳುಹಿಸುವುದಿಲ್ಲ.",
      promise_never_runs: "ಫೈಲ್ ಅನ್ನು ಎಂದಿಗೂ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವುದಿಲ್ಲ ಅಥವಾ ಚಲಾಯಿಸುವುದಿಲ್ಲ.",
      promise_lang: "ಇಂಗ್ಲಿಷ್ ಮತ್ತು ಕನ್ನಡದಲ್ಲಿ ವಿವರಿಸುತ್ತದೆ.",
      tab_apk: "ಆಪ್ ಅಥವಾ ಪ್ರೋಗ್ರಾಂ",
      tab_qr: "ಪಾವತಿ QR",
      drop_apk: "ಆಪ್ ಅಥವಾ ಪ್ರೋಗ್ರಾಂ ಫೈಲ್ ಅನ್ನು ಇಲ್ಲಿ ಹಾಕಿ",
      drop_qr: "QR ನ ಫೋಟೋ ಅಥವಾ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಇಲ್ಲಿ ಹಾಕಿ",
      drop_or: "ಅಥವಾ",
      drop_choose: "ಫೈಲ್ ಆಯ್ಕೆಮಾಡಿ",
      drop_apk_hint: "Android .apk ಅಥವಾ Windows .exe, 100 MB ವರೆಗೆ",
      drop_qr_hint: "PNG ಅಥವಾ JPG, 10 MB ವರೆಗೆ",
      clear_file: "ತೆಗೆದುಹಾಕಿ",
      link_label: "ಅಥವಾ UPI ಲಿಂಕ್ ಅಂಟಿಸಿ",
      shop_label: "ನೀವು ಪಾವತಿಸುತ್ತಿರುವ ಅಂಗಡಿ (ಐಚ್ಛಿಕ)",
      check_apk: "ಈ ಫೈಲ್ ಪರಿಶೀಲಿಸಿ",
      win_program: "ವಿಂಡೋಸ್ ಪ್ರೋಗ್ರಾಂ",
      check_qr: "ಈ QR ಪರಿಶೀಲಿಸಿ",
      samples_title: "ಫೈಲ್ ಇಲ್ಲವೇ? ಡೆಮೊ ಮಾದರಿಯನ್ನು ಪ್ರಯತ್ನಿಸಿ.",
      sample_go: "ಪರಿಶೀಲಿಸಿ",
      working: "ಫೈಲ್ ಓದಲಾಗುತ್ತಿದೆ, ಅಂಕ ನೀಡಲಾಗುತ್ತಿದೆ ಮತ್ತು Gemma ವಿವರಿಸುತ್ತಿದೆ…",
      err_network: "ScamShield ಸರ್ವರ್ ಸ್ಪಂದಿಸುತ್ತಿಲ್ಲ. ಅದು ಚಾಲನೆಯಲ್ಲಿದೆಯೇ ನೋಡಿ, ನಂತರ ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ.",
      err_apk_type: "ಒಂದು .apk ಫೈಲ್ ಆಯ್ಕೆಮಾಡಿ.",
      err_img_type: "QR ನ PNG ಅಥವಾ JPG ಚಿತ್ರವನ್ನು ಆಯ್ಕೆಮಾಡಿ.",
      verdict_Safe: "ಸುರಕ್ಷಿತ",
      verdict_Suspicious: "ಸಂಶಯಾಸ್ಪದ",
      verdict_Dangerous: "ಅಪಾಯಕಾರಿ",
      pays: "ಹಣ ಹೋಗುವುದು",
      expect_shop: "ನೀವು ನಿರೀಕ್ಷಿಸುವ ಅಂಗಡಿ",
      opens: "ತೆರೆಯುವುದು",
      text_qr: "ಪಠ್ಯ",
      risk_score: "ಅಪಾಯ ಅಂಕ",
      why_h: "ಕಾರಣಗಳು",
      none_found: "ಈ ಪರಿಶೀಲನೆಯಲ್ಲಿ ಯಾವುದೇ ಎಚ್ಚರಿಕೆಯ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ.",
      by_model: "Gemma ವಿವರಣೆ",
      by_rules: "ನಿಯಮ ವಿವರಣೆ",
      show_ev: "ಸಾಕ್ಷ್ಯ {id}",
      actions_h: "ಈಗ ಏನು ಮಾಡಬೇಕು",
      call: "1930 ಗೆ ಕರೆ ಮಾಡಿ",
      helpline_sub: "ರಾಷ್ಟ್ರೀಯ ಸೈಬರ್ ವಂಚನೆ ಸಹಾಯವಾಣಿ",
      report_online: "cybercrime.gov.in ನಲ್ಲಿ ದೂರು ನೀಡಿ",
      trail_h: "ScamShield ಹೇಗೆ ನಿರ್ಧರಿಸಿತು",
      t1: "ಕಂಡುಬಂದ ಸಾಕ್ಷ್ಯ",
      t1_v: "{n} ಅಂಶಗಳು",
      t1_n: "ಅವುಗಳಲ್ಲಿ {k} ಅಪಾಯ ಹೆಚ್ಚಿಸುತ್ತವೆ.",
      t1_n_one: "ಅವುಗಳಲ್ಲಿ 1 ಅಪಾಯ ಹೆಚ್ಚಿಸುತ್ತದೆ.",
      t1_n_none: "ಅವುಗಳಲ್ಲಿ ಯಾವುದೂ ಅಪಾಯ ಹೆಚ್ಚಿಸುವುದಿಲ್ಲ.",
      t2: "ನಿಯಮ ಅಂಕ",
      t2_n: "ನಿಯಮಗಳ ಪ್ರಕಾರ ಕನಿಷ್ಠ {floor}.",
      t3: "Gemma ವಿಶ್ಲೇಷಣೆ",
      t3_off: "ಬಳಸಲಾಗಿಲ್ಲ",
      t3_ok: "ಈ ಲ್ಯಾಪ್‌ಟಾಪ್‌ನಲ್ಲಿ {s} ಸೆಕೆಂಡುಗಳಲ್ಲಿ ಉತ್ತರಿಸಿತು.",
      t3_cached: "ಇದೇ ಫೈಲ್ ಮೊದಲು ಪರಿಶೀಲಿಸಲಾಗಿದೆ, ಆದ್ದರಿಂದ Gemma ಉತ್ತರವನ್ನು ತಕ್ಷಣ ಮರುಬಳಸಲಾಗಿದೆ.",
      t3_dropped: "ನಿಜವಾದ ಸಾಕ್ಷ್ಯವಿಲ್ಲದ {d} ಕಾರಣವನ್ನು ತೆಗೆದುಹಾಕಲಾಗಿದೆ.",
      t3_lang: "ಸರಿಯಾದ ಭಾಷೆಯಲ್ಲಿ ಇಲ್ಲದ {n} ವಾಕ್ಯವನ್ನು ಬದಲಾಯಿಸಲಾಗಿದೆ.",
      t3_unavailable: "ಮಾಡೆಲ್ ಚಾಲನೆಯಲ್ಲಿಲ್ಲ, ಆದ್ದರಿಂದ ನಿಗದಿತ ನಿಯಮ ವಿವರಣೆಗಳನ್ನು ಬಳಸಲಾಗಿದೆ.",
      t3_invalid: "ಮಾಡೆಲ್ ಉತ್ತರ ಎರಡು ಬಾರಿ ಸರಿಯಾಗಿರಲಿಲ್ಲ, ಆದ್ದರಿಂದ ನಿಯಮ ವಿವರಣೆಗಳನ್ನು ಬಳಸಲಾಗಿದೆ.",
      t4: "ಅಂತಿಮ ತೀರ್ಮಾನ",
      t4_raised: "Gemma {mv} ಎಂದಿತು, ಆದರೆ ನಿಯಮಗಳ ಪ್ರಕಾರ ಕನಿಷ್ಠ {floor}.",
      t4_model_higher: "ನಿಜವಾದ ಅಪಾಯದ ಸಾಕ್ಷ್ಯದೊಂದಿಗೆ Gemma ಇದನ್ನು ನಿಯಮ ಅಂಕಕ್ಕಿಂತ ಹೆಚ್ಚಿಸಿತು.",
      t4_capped: "Gemma {mv} ಎಂದಿತು, ಆದರೆ ನಿಜವಾದ ಅಪಾಯದ ಸಾಕ್ಷ್ಯ ನೀಡಲಿಲ್ಲ, ಆದ್ದರಿಂದ ನಿಯಮಗಳು ಇದನ್ನು {final} ಆಗಿ ಉಳಿಸಿದವು.",
      t4_agree: "Gemma ಮತ್ತು ನಿಯಮಗಳು ಒಪ್ಪುತ್ತವೆ.",
      t4_rules: "ನಿಯಮಗಳಿಂದ ನಿರ್ಧರಿಸಲಾಗಿದೆ.",
      ev_all: "ಎಲ್ಲಾ ಸಾಕ್ಷ್ಯ ನೋಡಿ ({n})",
      ev_id: "ID",
      ev_what: "ಇದು ಏನು",
      ev_found: "ಕಂಡುಬಂದದ್ದು",
      again: "ಇನ್ನೊಂದನ್ನು ಪರಿಶೀಲಿಸಿ",
      why_title: "ಇದು ಏಕೆ ಮುಖ್ಯ",
      why_statement: "2025 ರಲ್ಲಿ, ಭಾರತದ ಜನರು ಸೈಬರ್ ವಂಚನೆಯಿಂದ ₹19,813 ಕೋಟಿ ಕಳೆದುಕೊಂಡಿರುವುದಾಗಿ ವರದಿ ಮಾಡಿದ್ದಾರೆ. ಕರ್ನಾಟಕವೊಂದೇ ₹2,413 ಕೋಟಿ ಕಳೆದುಕೊಂಡಿದೆ, ಇದು ರಾಜ್ಯಗಳಲ್ಲಿ ಎರಡನೇ ಅತಿ ಹೆಚ್ಚು.",
      why_note: "ನಕಲಿ ಆಪ್ ಫೈಲ್‌ಗಳು ಮತ್ತು ನಕಲಿ ಪಾವತಿ QR ಗಳಿಗೆ ವಂಚಕರಿಗೆ ಯಾವುದೇ ಕೌಶಲ್ಯ ಬೇಕಿಲ್ಲ, ಮತ್ತು ಕಳೆದುಹೋದ ಹೆಚ್ಚಿನ ಹಣ ಮರಳಿ ಸಿಗುವುದಿಲ್ಲ. ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವ ಅಥವಾ ಪಾವತಿಸುವ ಮೊದಲು ಪರಿಶೀಲಿಸುವುದೇ ಹಣವನ್ನು ಉಳಿಸುತ್ತದೆ.",
      why_source: "ಮೂಲ: I4C ಡೇಟಾ, IANS ಮೂಲಕ",
      how_title: "ಪರಿಶೀಲನೆ ಹೇಗೆ ನಡೆಯುತ್ತದೆ",
      how1_t: "ಓದುತ್ತದೆ, ಎಂದಿಗೂ ಚಲಾಯಿಸುವುದಿಲ್ಲ",
      how1_p: "ScamShield APK ಅನ್ನು ZIP ಆರ್ಕೈವ್‌ನಂತೆ ತೆರೆದು ಅದರ ಅನುಮತಿಗಳು, ಸಹಿ ಪ್ರಮಾಣಪತ್ರ ಮತ್ತು ಕೋಡ್‌ನ ಪದಗಳನ್ನು ಓದುತ್ತದೆ. QR ಗೆ ಅದರ ಪಾವತಿ ಲಿಂಕ್ ಅನ್ನು ಡಿಕೋಡ್ ಮಾಡುತ್ತದೆ. ಏನನ್ನೂ ಇನ್‌ಸ್ಟಾಲ್ ಅಥವಾ ಚಲಾಯಿಸುವುದಿಲ್ಲ.",
      how2_t: "ಮುಕ್ತ ನಿಯಮಗಳಿಂದ ಅಂಕ",
      how2_p: "ಪ್ರತಿ ಕಂಡುಹಿಡಿತವೂ ಸಂಖ್ಯೆಯುಳ್ಳ ಸಾಕ್ಷ್ಯವಾಗುತ್ತದೆ. ಪ್ರಕಟಿತ ನಿಯಮಗಳು 0 ರಿಂದ 100 ರವರೆಗೆ ಅಂಕ ನೀಡುತ್ತವೆ. SMS ಓದುವುದು ಮತ್ತು ಟೆಲಿಗ್ರಾಮ್ ಬಾಟ್ ಲಿಂಕ್‌ನಂತಹ ಅಪಾಯಕಾರಿ ಸಂಯೋಜನೆಗಳಿಗೆ ಹೆಚ್ಚುವರಿ ತೂಕವಿದೆ.",
      how3_t: "Gemma ವಿವರಿಸುತ್ತದೆ, ನಿಯಮಗಳು ಕಾಯುತ್ತವೆ",
      how3_p: "ಈ ಲ್ಯಾಪ್‌ಟಾಪ್‌ನಲ್ಲೇ ಚಲಿಸುವ ಮುಕ್ತ ಮಾಡೆಲ್ Gemma 4 E4B, ಈ ಸಂಯೋಜನೆಯ ಅರ್ಥವನ್ನು ಕಂಡುಹಿಡಿದು ಸರಳವಾಗಿ ವಿವರಿಸುತ್ತದೆ. ಪ್ರತಿ ಕಾರಣವೂ ನಿಜವಾದ ಸಾಕ್ಷ್ಯವನ್ನು ಉಲ್ಲೇಖಿಸಬೇಕು. ಮಾಡೆಲ್ ಅಪಾಯದ ಮಟ್ಟವನ್ನು ಹೆಚ್ಚಿಸಬಹುದು, ಆದರೆ ಎಂದಿಗೂ ಕಡಿಮೆ ಮಾಡುವಂತಿಲ್ಲ.",
      limits_title: "ScamShield ಇನ್ನೂ ಮಾಡಲಾಗದ ವಿಷಯಗಳು",
      limit1: "ಸುಧಾರಿತ ಪ್ಯಾಕಿಂಗ್‌ನಿಂದ ಕೋಡ್ ಮರೆಮಾಡುವ ಆಪ್‌ಗಳು ಸ್ಥಿರ ಪರಿಶೀಲನೆಯಿಂದ ತಪ್ಪಿಸಿಕೊಳ್ಳಬಹುದು. ScamShield ತಿಳಿದಿರುವ ಪ್ಯಾಕರ್‌ಗಳನ್ನು ಗುರುತಿಸುತ್ತದೆ, ಆದರೆ ಇದು ಮೊದಲ ರಕ್ಷಣೆ ಮಾತ್ರ, ಆಂಟಿವೈರಸ್ ಅಲ್ಲ.",
      limit2: "UPI ID ಯ ನಿಜವಾದ ಮಾಲೀಕರು ಬ್ಯಾಂಕ್‌ಗಳಿಗೆ ಮಾತ್ರ ತಿಳಿದಿರುತ್ತಾರೆ. ಇಲ್ಲಿನ ಹೆಸರು ಪರಿಶೀಲನೆ ಡೆಮೊ ಡೇಟಾ ಬಳಸುತ್ತದೆ. ಆದ್ದರಿಂದ PIN ನಮೂದಿಸುವ ಮೊದಲು ನಿಮ್ಮ ಪಾವತಿ ಆಪ್ ತೋರಿಸುವ ಹೆಸರನ್ನು ಯಾವಾಗಲೂ ಓದಿ.",
      limit3: "ಕನ್ನಡ ವಿವರಣೆಗಳು ಸಣ್ಣ ಮಾಡೆಲ್ ಮತ್ತು ನಿಗದಿತ ಟೆಂಪ್ಲೇಟ್‌ಗಳಿಂದ ಬರುತ್ತವೆ. ಅವು ಸ್ಪಷ್ಟವಾಗಿವೆ, ಆದರೆ ವ್ಯಾಪಕ ಬಳಕೆಗೆ ಮೊದಲು ಕನ್ನಡ ಭಾಷಿಕರು ಪರಿಶೀಲಿಸಬೇಕು.",
      footer_license: "Apache-2.0 ಪರವಾನಗಿಯಡಿ ಮುಕ್ತ ಮೂಲ.",
      footer_model: "ವಿವರಣೆಗಳು Ollama ಮೂಲಕ ಸ್ಥಳೀಯವಾಗಿ ಚಲಿಸುವ Gemma 4 E4B ನಿಂದ.",
      footer_help: "ವಂಚನೆಯಿಂದ ಹಣ ಕಳೆದುಕೊಂಡಿರಾ? ಕರೆ ಮಾಡಿ",
      footer_or: "ಅಥವಾ ದೂರು ನೀಡಿ",
      footer_repo: "GitHub ನಲ್ಲಿ ಮೂಲ ಕೋಡ್",
    },
  };

  const ICONS = {
    sms: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4.5h16a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5H9l-4.5 3.5v-3.5H4A1.5 1.5 0 0 1 2.5 16V6A1.5 1.5 0 0 1 4 4.5z"/><path d="M7 9.5h10M7 13h6"/></svg>',
    exe: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/></svg>',
    apk: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 18h3"/></svg>',
    qr: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM18 18h3v3h-3z"/></svg>',
    report: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4.5 5.5v6c0 5 3.3 8.6 7.5 10 4.2-1.4 7.5-5 7.5-10v-6z"/><path d="m8.8 12 2.3 2.3 4.2-4.6"/></svg>',
    phone: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 3.5h3.2l1.6 4.2-2.1 1.4a11 11 0 0 0 5.2 5.2l1.4-2.1 4.2 1.6V17a2.5 2.5 0 0 1-2.7 2.5C9.6 19 5 14.4 4.5 6.2A2.5 2.5 0 0 1 5 3.5z"/></svg>',
  };

  // ------------------------------------------------------------------ state
  const state = {
    lang: "en",
    mode: "apk",
    result: null,
    health: null,
    samples: [],
  };
  try {
    const saved = localStorage.getItem("scamshield-lang");
    if (saved === "en" || saved === "kn") state.lang = saved;
  } catch (_) { /* storage unavailable: use default */ }

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const t = (key, params = {}) => {
    const s = (T[state.lang] && T[state.lang][key]) || T.en[key] || key;
    return s.replace(/\{(\w+)\}/g, (_, k) => (params[k] !== undefined ? params[k] : `{${k}}`));
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ------------------------------------------------------------------ language
  function applyLang() {
    document.documentElement.lang = state.lang;
    $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    $$("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    $$(".lang button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === state.lang)));
    renderStatus();
    renderSamples();
    if (state.result) renderReport(state.result, false);
  }

  $$(".lang button").forEach((btn) => btn.addEventListener("click", () => {
    state.lang = btn.dataset.lang;
    try { localStorage.setItem("scamshield-lang", state.lang); } catch (_) { /* ignore */ }
    applyLang();
  }));

  // ------------------------------------------------------------------ model status
  function renderStatus() {
    const pill = $("#modelPill");
    const text = $("#modelText");
    const h = state.health;
    if (!h) { pill.dataset.state = "checking"; text.textContent = t("status_checking"); return; }
    const model = (h.model && h.model.model) || "gemma4:e4b";
    const pretty = model.startsWith("gemma4") ? "Gemma 4 E4B" : model;
    if (!h.model_enabled) { pill.dataset.state = "fallback"; text.textContent = t("status_disabled"); }
    else if (h.model.reachable && h.model.installed) { pill.dataset.state = "ready"; text.textContent = t("status_ready", { model: pretty }); }
    else if (h.model.reachable) { pill.dataset.state = "fallback"; text.textContent = t("status_missing", { model }); }
    else { pill.dataset.state = "fallback"; text.textContent = t("status_off"); }
  }

  async function loadHealth() {
    try {
      const res = await fetch("/api/health");
      state.health = await res.json();
      const repo = $("#repoLink");
      if (state.health.repo_url) { repo.href = state.health.repo_url; repo.hidden = false; }
    } catch (_) {
      state.health = { model_enabled: true, model: { reachable: false, installed: false } };
    }
    renderStatus();
  }

  // ------------------------------------------------------------------ samples
  function renderSamples() {
    const list = $("#sampleList");
    if (!state.samples.length) { list.innerHTML = ""; return; }
    const forMode = (k) => (state.mode === "apk" ? k === "apk" || k === "exe" : k === state.mode);
    list.innerHTML = state.samples.filter((s) => forMode(s.kind)).map((s) => {
      const title = state.lang === "kn" && s.title_kn ? s.title_kn : s.title;
      const desc = state.lang === "kn" && s.description_kn ? s.description_kn : s.description;
      return `<li><button type="button" data-sample="${esc(s.id)}">
        <span class="sample-icon">${ICONS[s.kind] || ""}</span>
        <span><span class="sample-title">${esc(title)}</span><span class="sample-desc">${esc(desc)}</span></span>
        <span class="sample-go">${esc(t("sample_go"))}</span>
      </button></li>`;
    }).join("");
  }

  async function loadSamples() {
    try {
      const res = await fetch("/api/samples");
      state.samples = (await res.json()).samples || [];
    } catch (_) { state.samples = []; }
    renderSamples();
  }

  $("#sampleList").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-sample]");
    if (!btn) return;
    const sample = state.samples.find((s) => s.id === btn.dataset.sample);
    btn.setAttribute("aria-busy", "true");
    const label = sample ? (sample.file && sample.kind !== "qr" ? sample.file : (state.lang === "kn" && sample.title_kn) || sample.title) : "";
    runCheck(fetch(`/api/samples/${encodeURIComponent(btn.dataset.sample)}/check`, { method: "POST" }), label)
      .finally(() => btn.removeAttribute("aria-busy"));
  });

  // ------------------------------------------------------------------ tabs
  function setMode(mode, focus) {
    state.mode = mode;
    $$(".mode [role=tab]").forEach((tab) => {
      const on = tab.dataset.mode === mode;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      if (on && focus) tab.focus();
    });
    $("#panel-apk").hidden = mode !== "apk";
    $("#panel-qr").hidden = mode !== "qr";
    $("#panel-sms").hidden = mode !== "sms";
    hideError();
    renderSamples();
  }
  const MODES = ["apk", "qr", "sms"];
  $$(".mode [role=tab]").forEach((tab) => {
    tab.addEventListener("click", () => setMode(tab.dataset.mode, false));
    tab.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const step = e.key === "ArrowRight" ? 1 : MODES.length - 1;
        setMode(MODES[(MODES.indexOf(state.mode) + step) % MODES.length], true);
      }
    });
  });

  // ------------------------------------------------------------------ file inputs
  function wireDrop(form, kind) {
    const drop = $(".drop", form);
    const input = $("input[type=file]", form);
    const empty = $(".drop-empty", drop);
    const filled = $(".drop-file", drop);
    const nameEl = $(".file-name", drop);
    const thumb = $(".qr-thumb", drop);
    const submit = $("button[type=submit]", form);
    const link = $("input[name=link]", form);

    // App tab: accept any file. The server checks the real type from the file's bytes,
    // so a program renamed to .pdf or .apk is still caught.
    const valid = (file) => kind === "apk"
      ? true
      : /^image\//.test(file.type) || /\.(png|jpe?g|webp)$/i.test(file.name);

    const refresh = () => {
      const file = input.files && input.files[0];
      empty.hidden = !!file;
      filled.hidden = !file;
      if (file) {
        nameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
        if (thumb) {
          if (thumb.dataset.url) URL.revokeObjectURL(thumb.dataset.url);
          thumb.dataset.url = URL.createObjectURL(file);
          thumb.src = thumb.dataset.url;
        }
      } else if (thumb) {
        thumb.removeAttribute("src");
      }
      submit.disabled = !file && !(link && link.value.trim());
    };

    const setFile = (file) => {
      if (!file) return;
      if (!valid(file)) { showError(t(kind === "apk" ? "err_apk_type" : "err_img_type")); return; }
      hideError();
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      refresh();
    };

    input.addEventListener("change", () => {
      const file = input.files && input.files[0];
      if (file && !valid(file)) { input.value = ""; showError(t(kind === "apk" ? "err_apk_type" : "err_img_type")); }
      refresh();
    });
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
    drop.addEventListener("drop", (e) => setFile(e.dataTransfer.files && e.dataTransfer.files[0]));
    $(".clear", drop).addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); input.value = ""; refresh(); });
    if (link) link.addEventListener("input", refresh);

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (submit.disabled) return;
      const fd = new FormData();
      const file = input.files && input.files[0];
      if (file) fd.append("file", file);
      if (kind === "qr") {
        if (!file) fd.append("link", link.value.trim());
        fd.append("shop_name", $("input[name=shop_name]", form).value.trim());
      }
      submit.disabled = true;
      const label = file ? file.name : (link ? link.value.trim().slice(0, 60) : "");
      runCheck(fetch(`/api/check/${kind}`, { method: "POST", body: fd }), label).finally(refresh);
    });
    refresh();
  }

  function wireSms(form) {
    const text = $("textarea[name=text]", form);
    const sender = $("input[name=sender]", form);
    const submit = $("button[type=submit]", form);
    const refresh = () => { submit.disabled = !text.value.trim(); };
    text.addEventListener("input", refresh);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (submit.disabled) return;
      const fd = new FormData();
      fd.append("text", text.value);
      fd.append("sender", sender.value.trim());
      submit.disabled = true;
      const label = text.value.trim().replace(/\s+/g, " ").slice(0, 48) + (text.value.trim().length > 48 ? "…" : "");
      runCheck(fetch("/api/check/sms", { method: "POST", body: fd }), `“${label}”`).finally(refresh);
    });
    refresh();
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  function showError(msg) { const el = $("#formError"); el.textContent = msg; el.hidden = false; }
  function hideError() { $("#formError").hidden = true; }

  // ------------------------------------------------------------------ run a check
  let timer = null;
  function startTimer() {
    const el = $("#workingTime");
    const t0 = performance.now();
    el.textContent = "0.0";
    clearInterval(timer);
    timer = setInterval(() => { el.textContent = ((performance.now() - t0) / 1000).toFixed(1); }, 100);
  }
  function stopTimer() { clearInterval(timer); timer = null; }

  async function runCheck(request, label) {
    hideError();
    const wrap = $("#reportWrap");
    const working = $("#working");
    const report = $("#report");
    $("#workingName").textContent = label || "";
    wrap.hidden = false;
    working.hidden = false;
    report.hidden = true;
    startTimer();
    scrollIntoViewSoft(wrap);
    try {
      const res = await request;
      const data = await res.json().catch(() => ({}));
      stopTimer();
      if (!res.ok) {
        working.hidden = true;
        if (!state.result) wrap.hidden = true; else report.hidden = false;
        showError(data.error || data.detail || t("err_network"));
        scrollIntoViewSoft($("#checker"));
        return;
      }
      data._checkedAt = new Date().toISOString();
      data._checkId = makeCheckId(data);
      state.result = data;
      working.hidden = true;
      renderReport(data, true);
    } catch (_) {
      stopTimer();
      working.hidden = true;
      if (!state.result) wrap.hidden = true; else report.hidden = false;
      showError(t("err_network"));
    }
  }

  // A short, readable reference so a printed report can be quoted in a complaint.
  function makeCheckId(r) {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const seed = JSON.stringify(r.evidence || []) + d.getTime();
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    return `SS-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${h.toString(16).toUpperCase().slice(0, 4).padStart(4, "0")}`;
  }

  function scrollIntoViewSoft(el) {
    el.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" });
  }

  // ------------------------------------------------------------------ report
  const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3 };

  function renderReport(r, animate) {
    const L = state.lang;
    const report = $("#report");
    const evById = Object.fromEntries(r.evidence.map((e) => [e.id, e]));
    const verdictWord = (v) => t(`verdict_${v}`);

    // what was checked
    const m = r.meta || {};
    let checked = "";
    if (r.kind === "apk") {
      checked = `<strong>${esc(m.label)}</strong> <code>${esc(m.package)}</code>`;
    } else if (r.kind === "sms") {
      const msg = String(m.message || "");
      checked = `<span>${esc(t("msg_from"))}: ${m.sender ? `<code>${esc(m.sender)}</code>` : esc(t("msg_unknown_sender"))}</span>
        <blockquote class="msg-quote">${esc(msg.length > 280 ? msg.slice(0, 280) + "…" : msg)}</blockquote>`;
    } else if (r.kind === "exe") {
      checked = `<strong>${esc(m.file_name)}</strong> <code>${esc(t("win_program"))}</code>`;
    } else if (m.type === "upi") {
      checked = `${m.preview ? `<img src="${esc(m.preview)}" alt="">` : ""}
        <span>${esc(t("pays"))} <code>${esc(m.payee_upi)}</code></span>
        ${m.shop_name ? `<span>${esc(t("expect_shop"))}: <strong>${esc(m.shop_name)}</strong></span>` : ""}`;
    } else if (m.type === "web_link") {
      checked = `<span>${esc(t("opens"))} <code>${esc(m.raw)}</code></span>`;
    } else {
      checked = `<span>${esc(t("text_qr"))}: <code>${esc(m.raw)}</code></span>`;
    }

    // score meter
    const th = r.thresholds || { suspicious: 30, dangerous: 60 };
    const meter = `
      <div class="meter" aria-label="${esc(t("risk_score"))} ${r.score} / 100">
        <div class="meter-label"><span>${esc(t("risk_score"))}</span><b>${r.score} / 100</b></div>
        <div class="meter-track" aria-hidden="true">
          <span class="band-safe" style="width:${th.suspicious}%"></span>
          <span class="band-warn" style="width:${th.dangerous - th.suspicious}%"></span>
          <span class="band-danger" style="width:${100 - th.dangerous}%"></span>
          <i class="meter-marker" style="left:${Math.min(98.5, Math.max(1.5, r.score))}%"></i>
        </div>
        <div class="meter-scale" aria-hidden="true"><span>0</span><span>100</span></div>
      </div>`;

    // reasons
    const reasons = r.reasons.length
      ? `<ul class="reasons">${r.reasons.map((reason) => {
          const sev = reason.evidence_ids.reduce((best, id) => {
            const s = (evById[id] && evById[id].severity) || "info";
            return SEV_RANK[s] > SEV_RANK[best] ? s : best;
          }, "info");
          const chips = reason.evidence_ids.map((id) =>
            `<button type="button" class="chip" data-ev="${esc(id)}" aria-label="${esc(t("show_ev", { id }))}">${esc(id)}</button>`).join("");
          return `<li class="reason" data-sev="${sev}">
            <p lang="${L}">${esc(reason[L] || reason.en)}</p>
            <div class="reason-meta">${chips}<span class="by">${esc(t(reason.source === "model" ? "by_model" : "by_rules"))}</span></div>
          </li>`;
        }).join("")}</ul>`
      : `<p class="no-reasons">${esc(t("none_found"))}</p>`;

    // next steps
    const steps = (r[`next_steps_${L}`] || r.next_steps_en).map((s) => `<li>${esc(s)}</li>`).join("");

    // decision trail
    const ai = r.ai || {};
    const risky = r.evidence.filter((e) => e.severity !== "info").length;
    let t3Value, t3Note;
    if (ai.used) {
      t3Value = ai.model_verdict ? `<span class="v-${ai.model_verdict}">${esc(verdictWord(ai.model_verdict))}</span>` : esc(t("t3_off"));
      t3Note = ai.cached ? t("t3_cached") : t("t3_ok", { s: (ai.latency_ms / 1000).toFixed(1) });
      if (ai.dropped_reasons) t3Note += " " + t("t3_dropped", { d: ai.dropped_reasons });
      if (ai.fixed_language) t3Note += " " + t("t3_lang", { n: ai.fixed_language });
    } else {
      t3Value = esc(t("t3_off"));
      t3Note = ai.status === "invalid_json" ? t("t3_invalid") : t("t3_unavailable");
    }
    let t4Note;
    if (!ai.used || !ai.model_verdict) t4Note = t("t4_rules");
    else if (ai.capped_by_rules) t4Note = t("t4_capped", { mv: verdictWord(ai.model_verdict), final: verdictWord(r.verdict) });
    else if (ai.raised_by_rules) t4Note = t("t4_raised", { mv: verdictWord(ai.model_verdict), floor: verdictWord(r.rule_floor) });
    else if (ai.model_verdict !== r.rule_floor) t4Note = t("t4_model_higher");
    else t4Note = t("t4_agree");

    const trail = `
      <section class="trail" aria-labelledby="trail-h">
        <h3 id="trail-h">${esc(t("trail_h"))}</h3>
        <ol class="trail-steps">
          <li><span class="t-label">${esc(t("t1"))}</span><span class="t-value">${esc(t("t1_v", { n: r.evidence.length }))}</span><span class="t-note">${esc(t(risky === 0 ? "t1_n_none" : risky === 1 ? "t1_n_one" : "t1_n", { k: risky }))}</span></li>
          <li><span class="t-label">${esc(t("t2"))}</span><span class="t-value">${r.score} / 100</span><span class="t-note">${esc(t("t2_n", { floor: verdictWord(r.rule_floor) }))}</span></li>
          <li><span class="t-label">${esc(t("t3"))}</span><span class="t-value">${t3Value}</span><span class="t-note">${esc(t3Note)}</span></li>
          <li><span class="t-label">${esc(t("t4"))}</span><span class="t-value v-${r.verdict}">${esc(verdictWord(r.verdict))}</span><span class="t-note">${esc(t4Note)}</span></li>
        </ol>
        <details class="evidence" id="evidence">
          <summary>${esc(t("ev_all", { n: r.evidence.length }))}</summary>
          <table class="ev-table">
            <thead><tr><th>${esc(t("ev_id"))}</th><th>${esc(t("ev_what"))}</th><th>${esc(t("ev_found"))}</th></tr></thead>
            <tbody>${r.evidence.map((e) => `
              <tr id="ev-${esc(e.id)}"><td>${esc(e.id)}</td><td><span class="sev sev-${e.severity}" aria-hidden="true"></span>${esc(e.label)}</td><td>${esc(e.value)}</td></tr>`).join("")}
            </tbody>
          </table>
        </details>
      </section>`;

    const when = r._checkedAt ? new Date(r._checkedAt).toLocaleString(L === "kn" ? "kn-IN" : "en-IN",
      { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
    report.dataset.verdict = r.verdict;
    report.innerHTML = `
      <div class="report-doc">
        <p class="doc-title">${ICONS.report}<span>${esc(t("report_title"))}</span></p>
        <dl class="doc-meta">
          <div><dt>${esc(t("report_id"))}</dt><dd>${esc(r._checkId || "")}</dd></div>
          <div><dt>${esc(t("report_time"))}</dt><dd>${esc(when)}</dd></div>
          <div><dt>${esc(t("report_where"))}</dt><dd>${esc(t("report_device"))}</dd></div>
        </dl>
      </div>
      <div class="report-head">
        <div class="stamp" lang="${L}" role="img" aria-label="${esc(verdictWord(r.verdict))}">${esc(verdictWord(r.verdict))}</div>
        <div class="head-copy">
          <p class="summary" lang="${L}">${esc(r[`summary_${L}`] || r.summary_en)}</p>
          <div class="checked-item">${checked}</div>
          ${meter}
        </div>
      </div>
      <div class="report-body">
        <section class="reasons-col" aria-labelledby="why-h">
          <h3 id="why-h">${esc(t("why_h"))}</h3>
          ${reasons}
        </section>
        <section class="actions" aria-labelledby="act-h">
          <h3 id="act-h">${esc(t("actions_h"))}</h3>
          <a class="helpline" href="tel:1930">${ICONS.phone}<b>${esc(t("call"))}</b><span>${esc(t("helpline_sub"))}</span></a>
          <a class="report-link" href="https://cybercrime.gov.in" target="_blank" rel="noopener">${esc(t("report_online"))}</a>
          <ol class="steps">${steps}</ol>
        </section>
      </div>
      ${trail}
      <div class="report-foot">
        <span>${esc((r.disclaimer && r.disclaimer[L]) || "")}</span>
        <span class="foot-actions"><button type="button" class="btn-quiet print">${esc(t("print"))}</button><button type="button" class="btn-quiet again">${esc(t("again"))}</button></span>
      </div>`;
    report.hidden = false;

    if (animate) {
      const stamp = $(".stamp", report);
      if (!reducedMotion()) stamp.classList.add("is-landing");
      report.focus({ preventScroll: true });
      scrollIntoViewSoft($("#reportWrap"));
    }
  }

  $("#report").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip[data-ev]");
    if (chip) {
      const details = $("#evidence");
      details.open = true;
      const row = document.getElementById(`ev-${chip.dataset.ev}`);
      if (row) {
        row.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "center" });
        row.classList.add("is-flash");
        setTimeout(() => row.classList.remove("is-flash"), 1400);
      }
      return;
    }
    if (e.target.closest(".print")) {
      const details = $("#evidence");
      if (details) details.open = true;
      window.print();
      return;
    }
    if (e.target.closest(".again")) {
      scrollIntoViewSoft($("#checker"));
      const tab = $(`.mode [data-mode="${state.mode}"]`);
      if (tab) tab.focus({ preventScroll: true });
    }
  });

  // ------------------------------------------------------------------ boot
  wireDrop($("#panel-apk"), "apk");
  wireDrop($("#panel-qr"), "qr");
  wireSms($("#panel-sms"));
  applyLang();
  loadHealth();
  loadSamples();
})();
