"""Build the harmless demo samples used in the ScamShield demo.

Creates, in samples/out/:
  fake_rto_challan.apk   - looks like a scam app (SMS + accessibility + Telegram bot URL,
                           debug certificate, "RTO Challan" name). Contains NO code.
  simple_calculator.apk  - a clean app for contrast. Contains NO code.
  qr_shop.png            - normal shop payment QR (expected: Safe)
  qr_cashback.png        - "scan to receive cashback" QR (expected: Dangerous)
  qr_sticker.png         - another shop's QR pasted over the one you expect (expected: Suspicious)
  samples.json           - list of samples for the web app

SAFETY: the APKs are built from scratch by this script. They hold a binary
manifest, a DEX file containing only a string table (no classes, no methods,
nothing executable) and a v1 JAR signature. They cannot do anything even if
someone tried to install them, and ScamShield never installs them anyway.

Usage:
    python samples/make_demo_samples.py
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
DEMO_MARKER = "SCAMSHIELD_HARMLESS_DEMO_SAMPLE_NO_EXECUTABLE_CODE"

# Android framework attribute resource IDs
ATTR_IDS = {
    "label": 0x01010001,
    "name": 0x01010003,
    "permission": 0x01010006,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
}
TYPE_STRING, TYPE_INT_DEC = 0x03, 0x10
NO_INDEX = 0xFFFFFFFF


# --------------------------------------------------------------------------- AXML
class AxmlWriter:
    """Minimal binary Android XML (AXML) encoder, enough for an AndroidManifest."""

    def __init__(self) -> None:
        # attribute names that carry resource IDs must come first, in map order
        self.strings: list[str] = list(ATTR_IDS)
        self.chunks: list[bytes] = []

    def idx(self, s: str) -> int:
        if s not in self.strings:
            self.strings.append(s)
        return self.strings.index(s)

    @staticmethod
    def _node(chunk_type: int, body: bytes) -> bytes:
        header = struct.pack("<HHI", chunk_type, 0x10, 0x10 + len(body))
        return header + struct.pack("<II", 1, NO_INDEX) + body

    def start_ns(self, prefix: str, uri: str) -> None:
        self.chunks.append(self._node(0x0100, struct.pack("<II", self.idx(prefix), self.idx(uri))))

    def end_ns(self, prefix: str, uri: str) -> None:
        self.chunks.append(self._node(0x0101, struct.pack("<II", self.idx(prefix), self.idx(uri))))

    def start(self, tag: str, attrs: list[tuple[str | None, str, object]]) -> None:
        name_idx = self.idx(tag)
        body = struct.pack("<IIHHHHHH", NO_INDEX, name_idx, 0x14, 0x14, len(attrs), 0, 0, 0)
        for ns, attr, value in attrs:
            ns_idx = self.idx(ANDROID_NS) if ns else NO_INDEX
            a_idx = self.idx(attr)
            if isinstance(value, int):
                raw, dtype, data = NO_INDEX, TYPE_INT_DEC, value
            else:
                v_idx = self.idx(str(value))
                raw, dtype, data = v_idx, TYPE_STRING, v_idx
            body += struct.pack("<IIIHBBI", ns_idx, a_idx, raw, 8, 0, dtype, data)
        self.chunks.append(self._node(0x0102, body))

    def end(self, tag: str) -> None:
        self.chunks.append(self._node(0x0103, struct.pack("<II", NO_INDEX, self.idx(tag))))

    def _string_pool(self) -> bytes:
        offsets, data = [], b""
        for s in self.strings:
            offsets.append(len(data))
            enc = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        n = len(self.strings)
        strings_start = 0x1C + 4 * n
        size = strings_start + len(data)
        return (struct.pack("<HHIIIIII", 0x0001, 0x1C, size, n, 0, 0, strings_start, 0)
                + b"".join(struct.pack("<I", o) for o in offsets) + data)

    def build(self) -> bytes:
        pool = self._string_pool()
        resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ATTR_IDS)) + b"".join(
            struct.pack("<I", v) for v in ATTR_IDS.values())
        body = pool + resmap + b"".join(self.chunks)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def build_manifest(package: str, label: str, version_name: str, permissions: list[str],
                   accessibility_service: bool) -> bytes:
    w = AxmlWriter()
    w.start_ns("android", ANDROID_NS)
    w.start("manifest", [(None, "package", package), (ANDROID_NS, "versionCode", 3),
                         (ANDROID_NS, "versionName", version_name)])
    w.start("uses-sdk", [(ANDROID_NS, "minSdkVersion", 23), (ANDROID_NS, "targetSdkVersion", 33)])
    w.end("uses-sdk")
    for perm in permissions:
        w.start("uses-permission", [(ANDROID_NS, "name", perm)])
        w.end("uses-permission")
    w.start("application", [(ANDROID_NS, "label", label)])
    w.start("activity", [(ANDROID_NS, "name", ".MainActivity")])
    w.end("activity")
    if accessibility_service:
        w.start("service", [(ANDROID_NS, "name", ".SyncService"),
                            (ANDROID_NS, "permission", "android.permission.BIND_ACCESSIBILITY_SERVICE")])
        w.end("service")
    w.end("application")
    w.end("manifest")
    w.end_ns("android", ANDROID_NS)
    return w.build()


# ---------------------------------------------------------------------------- DEX
def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_dex(strings: list[str]) -> bytes:
    """A valid DEX file with ONLY a string table: no types, methods or classes."""
    strings = sorted(set(strings))
    n = len(strings)
    string_ids_off = 0x70
    data_off = string_ids_off + 4 * n
    data = b""
    offsets = []
    for s in strings:
        offsets.append(data_off + len(data))
        data += _uleb128(len(s)) + s.encode("utf-8") + b"\x00"
    while (data_off + len(data)) % 4:
        data += b"\x00"
    map_off = data_off + len(data)
    map_items = [(0x0000, 1, 0), (0x0001, n, string_ids_off), (0x2002, n, data_off), (0x1000, 1, map_off)]
    map_list = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", t, 0, size, off) for t, size, off in map_items)
    file_size = map_off + len(map_list)
    header_rest = struct.pack(
        "<IIIIIIIIIIIIIIIIIIII",
        file_size, 0x70, 0x12345678, 0, 0, map_off, n, string_ids_off,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, file_size - data_off, data_off)
    body = header_rest + b"".join(struct.pack("<I", o) for o in offsets) + data + map_list
    signature = hashlib.sha1(body).digest()
    checksum = zlib.adler32(signature + body) & 0xFFFFFFFF
    return b"dex\n035\x00" + struct.pack("<I", checksum) + signature + body


# ------------------------------------------------------------------- v1 signing
def _make_cert(common_name: str, org: str, country: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


def _b64sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def write_signed_apk(path: Path, files: dict[str, bytes], cert_subject: tuple[str, str, str]) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    sections = []
    for name, content in files.items():
        sections.append((name, f"Name: {name}\r\nSHA-256-Digest: {_b64sha256(content)}\r\n\r\n".encode()))
    manifest = b"Manifest-Version: 1.0\r\nCreated-By: ScamShield demo builder\r\n\r\n" + b"".join(
        s for _, s in sections)
    sf = (b"Signature-Version: 1.0\r\nCreated-By: ScamShield demo builder\r\n"
          + f"SHA-256-Digest-Manifest: {_b64sha256(manifest)}\r\n\r\n".encode()
          + b"".join(f"Name: {name}\r\nSHA-256-Digest: {_b64sha256(sec)}\r\n\r\n".encode()
                     for name, sec in sections))
    key, cert = _make_cert(*cert_subject)
    sig = (pkcs7.PKCS7SignatureBuilder().set_data(sf).add_signer(cert, key, hashes.SHA256())
           .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.writestr("META-INF/CERT.SF", sf)
        zf.writestr("META-INF/CERT.RSA", sig)


# ----------------------------------------------------------------------- samples
def build_fake_apk(path: Path) -> None:
    pkg = "com.rtochallan.payonline"
    manifest = build_manifest(pkg, "RTO Challan", "1.3", [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    ], accessibility_service=True)
    dex = build_dex([
        DEMO_MARKER,
        "Lcom/rtochallan/payonline/MainActivity;",
        "Lcom/rtochallan/payonline/SmsReceiver;",
        "Lcom/rtochallan/payonline/SyncService;",
        "https://api.telegram.org/botDEMO_NOT_REAL/sendMessage",
        "chat_id",
        "sms_body",
        "Your e-challan of Rs 500 is pending. Pay now to avoid court action.",
        "Enter the OTP sent to your phone",
        "Enter UPI PIN to pay challan",
        "Complete your KYC",
    ])
    write_signed_apk(path, {"AndroidManifest.xml": manifest, "classes.dex": dex},
                     ("Android Debug", "Android", "US"))


def build_safe_apk(path: Path) -> None:
    pkg = "org.scamshield.demo.calculator"
    manifest = build_manifest(pkg, "Simple Calculator", "2.0", [
        "android.permission.VIBRATE",
    ], accessibility_service=False)
    dex = build_dex([
        DEMO_MARKER,
        "Lorg/scamshield/demo/calculator/MainActivity;",
        "Lorg/scamshield/demo/calculator/Calculator;",
        "add", "subtract", "multiply", "divide", "Simple Calculator",
    ])
    write_signed_apk(path, {"AndroidManifest.xml": manifest, "classes.dex": dex},
                     ("ScamShield Demo Labs", "ScamShield", "IN"))


def build_fake_kyc_apk(path: Path) -> None:
    """Fake bank 'KYC update' app: SMS theft plus a fake login screen over other apps,
    reporting to a bare IP address (a reserved documentation address, unreachable)."""
    manifest = build_manifest("com.sbi.kycupdate.online", "SBI KYC Update", "4.2", [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ], accessibility_service=False)
    dex = build_dex([
        DEMO_MARKER,
        "Lcom/sbi/kycupdate/online/MainActivity;",
        "Lcom/sbi/kycupdate/online/OverlayLogin;",
        "http://203.0.113.45:8080/api/upload",
        "Your SBI account will be blocked today. Update PAN and KYC now.",
        "Enter net banking user ID and password",
        "Enter debit card number, expiry and CVV",
        "Enter the OTP sent to your registered mobile",
    ])
    write_signed_apk(path, {"AndroidManifest.xml": manifest, "classes.dex": dex},
                     ("Android Debug", "Android", "US"))


def build_fake_pmkisan_apk(path: Path) -> None:
    """Fake government-scheme app that hides its code with a packer and installs more apps."""
    manifest = build_manifest("com.pmkisan.status.check", "PM Kisan Yojana 2026", "1.0", [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
    ], accessibility_service=False)
    dex = build_dex([
        DEMO_MARKER,
        "Lcom/stub/StubApp;",
        "Check your PM Kisan installment status",
        "Install update to receive Rs 6000",
    ])
    files = {
        "AndroidManifest.xml": manifest,
        "classes.dex": dex,
        # Empty placeholder named like a real packer library: the name is the signal.
        "lib/arm64-v8a/libjiagu.so": b"",
        "assets/payload.bin": b"\x00" * 64,
    }
    write_signed_apk(path, files, ("Android Debug", "Android", "US"))


def build_loan_apk(path: Path) -> None:
    """Instant-loan app that grabs contacts, call history and SMS: suspicious, not proven theft."""
    manifest = build_manifest("com.quickcash.instantloan", "QuickCash Instant Loan", "3.1", [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
    ], accessibility_service=False)
    dex = build_dex([
        DEMO_MARKER,
        "Lcom/quickcash/instantloan/MainActivity;",
        "https://quickcash-demo-0000.firebaseio.com/users",
        "Get Rs 50,000 loan in 5 minutes. No documents.",
        "Allow access to contacts to continue",
    ])
    write_signed_apk(path, {"AndroidManifest.xml": manifest, "classes.dex": dex},
                     ("QuickCash Fintech", "QuickCash", "IN"))


def build_pe(sections: list[str], strings: list[str], signed: bool) -> bytes:
    """A Windows PE file with headers, named sections and a string table, but NO code.

    AddressOfEntryPoint and SizeOfImage are 0, so Windows refuses to start it
    ("not a valid application"). ScamShield only reads these bytes.
    """
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt_size = 0xE0
    n = len(sections)
    header_end = e_lfanew + 24 + opt_size + 40 * n
    data_off = (header_end + 0x1FF) & ~0x1FF
    blob = ("\0".join([DEMO_MARKER] + strings) + "\0").encode("ascii")
    blob += b"\0" * (-len(blob) % 0x200)
    sig = b"\0" * 64 if signed else b""

    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, n, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)        # PE32
    struct.pack_into("<I", opt, 92, 16)          # NumberOfRvaAndSizes
    if signed:                                   # security directory -> signature block
        struct.pack_into("<II", opt, 96 + 4 * 8, data_off + len(blob), len(sig))
    table = b""
    for i, name in enumerate(sections):
        raw = blob if i == 0 else b""
        table += struct.pack("<8sIIIIIIHHI", name.encode()[:8], len(raw), 0x1000 * (i + 1),
                             len(raw), data_off if raw else 0, 0, 0, 0, 0, 0x40000040)
    head = bytes(dos) + coff + bytes(opt) + table
    head += b"\0" * (data_off - len(head))
    return head + blob + sig


def build_exes() -> None:
    # 1. A "PDF receipt" that is really a program with keylogger functions and a Telegram bot.
    (OUT / "Traffic_Challan_Receipt.pdf.exe").write_bytes(build_pe(
        [".text", ".rdata"],
        ["GetAsyncKeyState", "SetWindowsHookExA", "user32.dll",
         "https://api.telegram.org/botDEMO_NOT_REAL/sendDocument",
         "Your e-challan receipt", "Enter net banking password"],
        signed=False))
    # 2. A packed program renamed to .apk, so it looks like a phone app.
    (OUT / "PM_Kisan_Update.apk").write_bytes(build_pe(
        ["UPX0", "UPX1", ".rsrc"],
        ["PM Kisan beneficiary status", "kernel32.dll"],
        signed=False))
    # 3. An ordinary signed installer, for contrast.
    (OUT / "PhotoViewer_Setup.exe").write_bytes(build_pe(
        [".text", ".rdata", ".rsrc"],
        ["Photo Viewer setup", "kernel32.dll", "Choose install folder"],
        signed=True))


QR_SAMPLES = [
    {
        "id": "qr_shop",
        "file": "qr_shop.png",
        "payload": "upi://pay?pa=sharmastores@okaxis&pn=Sharma%20General%20Store&cu=INR",
        "shop_name": "Sharma General Store",
        "title": "Shop counter QR",
        "description": "The QR at Sharma General Store's counter.",
        "title_kn": "ಅಂಗಡಿಯ ಕೌಂಟರ್ QR",
        "description_kn": "ಶರ್ಮಾ ಜನರಲ್ ಸ್ಟೋರ್‌ನ ಕೌಂಟರ್‌ನಲ್ಲಿರುವ QR.",
        "expected": "Safe",
    },
    {
        "id": "qr_cashback",
        "file": "qr_cashback.png",
        "payload": ("upi://pay?pa=9876501234@ybl&pn=Receive%20Cashback&am=5000"
                    "&tn=Scan%20to%20receive%20Rs%205000%20cashback&cu=INR"),
        "shop_name": "",
        "title": "“Scan to receive ₹5,000”",
        "description": "Sent on WhatsApp by someone buying your old sofa.",
        "title_kn": "“₹5,000 ಪಡೆಯಲು ಸ್ಕ್ಯಾನ್ ಮಾಡಿ”",
        "description_kn": "ನಿಮ್ಮ ಹಳೆಯ ಸೋಫಾ ಖರೀದಿಸುವವರು WhatsApp ನಲ್ಲಿ ಕಳುಹಿಸಿದ QR.",
        "expected": "Dangerous",
    },
    {
        "id": "qr_sticker",
        "file": "qr_sticker.png",
        "payload": "upi://pay?pa=ganeshstores@okicici&pn=Sri%20Ganesh%20Stores&cu=INR",
        "shop_name": "Sharma General Store",
        "title": "Sticker over the shop QR",
        "description": "You are paying Sharma General Store, but this QR was stuck on top.",
        "title_kn": "ಅಂಗಡಿ QR ಮೇಲೆ ಅಂಟಿಸಿದ ಸ್ಟಿಕ್ಕರ್",
        "description_kn": "ನೀವು ಶರ್ಮಾ ಜನರಲ್ ಸ್ಟೋರ್‌ಗೆ ಪಾವತಿಸುತ್ತಿದ್ದೀರಿ, ಆದರೆ ಈ QR ಮೇಲೆ ಅಂಟಿಸಲಾಗಿತ್ತು.",
        "expected": "Suspicious",
    },
]


# Demo messages. Links use reserved or non-working addresses and are never opened.
SMS_SAMPLES = [
    {"id": "sms_power", "kind": "sms", "expected": "Dangerous",
     "title": "Electricity disconnection SMS", "description": "Says your power will be cut tonight.",
     "title_kn": "ವಿದ್ಯುತ್ ಕಡಿತದ SMS", "description_kn": "ಇಂದು ರಾತ್ರಿ ವಿದ್ಯುತ್ ಕಡಿತವಾಗುತ್ತದೆ ಎನ್ನುತ್ತದೆ.",
     "sender": "+91 98123 45678",
     "text": ("Dear Consumer, your electricity power will be disconnected tonight at 9.30 pm because "
              "your previous month bill was not updated. Please immediately contact our electricity "
              "officer 9876543210. Thank you.")},
    {"id": "sms_kyc", "kind": "sms", "expected": "Dangerous",
     "title": "SBI KYC update SMS", "description": "Account blocked unless you click a link.",
     "title_kn": "SBI KYC ಅಪ್‌ಡೇಟ್ SMS", "description_kn": "ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡದಿದ್ದರೆ ಖಾತೆ ಬ್ಲಾಕ್ ಎನ್ನುತ್ತದೆ.",
     "sender": "+91 70123 45678",
     "text": ("Dear SBI user, your YONO account will be blocked today. Update your PAN/KYC "
              "immediately: http://sbi-kyc-update.example/login")},
    {"id": "sms_job", "kind": "sms", "expected": "Dangerous",
     "title": "Part-time job WhatsApp", "description": "Earn daily by liking YouTube videos.",
     "title_kn": "ಪಾರ್ಟ್-ಟೈಮ್ ಉದ್ಯೋಗ WhatsApp", "description_kn": "ವಿಡಿಯೋ ಲೈಕ್ ಮಾಡಿ ದಿನವೂ ಗಳಿಸಿ ಎನ್ನುತ್ತದೆ.",
     "sender": "+91 98450 12345",
     "text": ("Hello! We are hiring for part-time work from home. Earn Rs 3,000 to Rs 8,000 daily by "
              "liking YouTube videos. Contact HR on Telegram: https://t.me/demo_hr_desk")},
    {"id": "sms_arrest", "kind": "sms", "expected": "Dangerous",
     "title": "\u201cCyber Crime Branch\u201d message", "description": "A drugs parcel and an arrest threat.",
     "title_kn": "\u201cಸೈಬರ್ ಕ್ರೈಮ್ ಬ್ರಾಂಚ್\u201d ಸಂದೇಶ", "description_kn": "ಡ್ರಗ್ಸ್ ಪಾರ್ಸೆಲ್ ಮತ್ತು ಬಂಧನದ ಬೆದರಿಕೆ.",
     "sender": "",
     "text": ("This is Mumbai Cyber Crime Branch. A parcel in your name containing drugs has been seized "
              "by customs. Your Aadhaar is linked to money laundering. Join the video call immediately "
              "or an arrest warrant will be issued.")},
    {"id": "sms_otp", "kind": "sms", "expected": "Safe",
     "title": "Genuine bank OTP", "description": "A real-style OTP message, for comparison.",
     "title_kn": "ನಿಜವಾದ ಬ್ಯಾಂಕ್ OTP", "description_kn": "ಹೋಲಿಕೆಗಾಗಿ ನಿಜವಾದ ಮಾದರಿಯ OTP ಸಂದೇಶ.",
     "sender": "AX-HDFCBK",
     "text": ("482913 is your OTP for a transaction of Rs 1,250.00 at AMAZON on your HDFC Bank card "
              "ending 4417. Valid for 10 minutes. Do not share this OTP with anyone. -HDFC Bank")},
]


def build_qrs() -> None:
    import qrcode

    for s in QR_SAMPLES:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
        qr.add_data(s["payload"])
        qr.make(fit=True)
        qr.make_image(fill_color="black", back_color="white").save(OUT / s["file"])


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    build_fake_apk(OUT / "fake_rto_challan.apk")
    build_safe_apk(OUT / "simple_calculator.apk")
    build_fake_kyc_apk(OUT / "fake_sbi_kyc_update.apk")
    build_fake_pmkisan_apk(OUT / "fake_pm_kisan.apk")
    build_loan_apk(OUT / "quickcash_loan.apk")
    build_exes()
    build_qrs()
    samples = [
        {"id": "apk_fake", "kind": "apk", "file": "fake_rto_challan.apk",
         "title": "“RTO Challan” app",
         "description": "A file forwarded on WhatsApp about a pending traffic fine.",
         "title_kn": "“RTO ಚಲನ್” ಆಪ್",
         "description_kn": "ಬಾಕಿ ಇರುವ ಟ್ರಾಫಿಕ್ ದಂಡದ ಬಗ್ಗೆ WhatsApp ನಲ್ಲಿ ಬಂದ ಫೈಲ್.",
         "expected": "Dangerous"},
        {"id": "apk_safe", "kind": "apk", "file": "simple_calculator.apk",
         "title": "Simple Calculator app",
         "description": "An ordinary app, for comparison.",
         "title_kn": "ಸರಳ ಕ್ಯಾಲ್ಕುಲೇಟರ್ ಆಪ್",
         "description_kn": "ಹೋಲಿಕೆಗಾಗಿ ಒಂದು ಸಾಮಾನ್ಯ ಆಪ್.",
         "expected": "Safe"},
        {"id": "apk_kyc", "kind": "apk", "file": "fake_sbi_kyc_update.apk",
         "title": "“SBI KYC Update” app",
         "description": "SMS says your bank account will be blocked unless you install this.",
         "title_kn": "“SBI KYC ಅಪ್‌ಡೇಟ್” ಆಪ್",
         "description_kn": "ಇದನ್ನು ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡದಿದ್ದರೆ ಬ್ಯಾಂಕ್ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ ಎಂದು SMS ಹೇಳುತ್ತದೆ.",
         "expected": "Dangerous"},
        {"id": "apk_pmkisan", "kind": "apk", "file": "fake_pm_kisan.apk",
         "title": "“PM Kisan Yojana 2026” app",
         "description": "Shared in a farmers' group to “check your installment”.",
         "title_kn": "“PM ಕಿಸಾನ್ ಯೋಜನೆ 2026” ಆಪ್",
         "description_kn": "“ನಿಮ್ಮ ಕಂತು ಪರಿಶೀಲಿಸಿ” ಎಂದು ರೈತರ ಗುಂಪಿನಲ್ಲಿ ಹಂಚಲಾಗಿದೆ.",
         "expected": "Dangerous"},
        {"id": "apk_loan", "kind": "apk", "file": "quickcash_loan.apk",
         "title": "“QuickCash Instant Loan” app",
         "description": "Promises a loan in 5 minutes with no documents.",
         "title_kn": "“QuickCash ತ್ವರಿತ ಸಾಲ” ಆಪ್",
         "description_kn": "ದಾಖಲೆಗಳಿಲ್ಲದೆ 5 ನಿಮಿಷದಲ್ಲಿ ಸಾಲದ ಭರವಸೆ ನೀಡುತ್ತದೆ.",
         "expected": "Suspicious"},
        {"id": "exe_receipt", "kind": "exe", "file": "Traffic_Challan_Receipt.pdf.exe",
         "title": "\u201cTraffic_Challan_Receipt.pdf\u201d",
         "description": "An email attachment that looks like a PDF receipt.",
         "title_kn": "\u201cಟ್ರಾಫಿಕ್ ಚಲನ್ ರಸೀದಿ.pdf\u201d",
         "description_kn": "PDF ರಸೀದಿಯಂತೆ ಕಾಣುವ ಇಮೇಲ್ ಲಗತ್ತು.",
         "expected": "Dangerous"},
        {"id": "exe_renamed", "kind": "exe", "file": "PM_Kisan_Update.apk",
         "title": "\u201cPM_Kisan_Update.apk\u201d (really a Windows program)",
         "description": "Named like a phone app, but it is a program in disguise.",
         "title_kn": "\u201cPM_Kisan_Update.apk\u201d (ನಿಜವಾಗಿ ವಿಂಡೋಸ್ ಪ್ರೋಗ್ರಾಂ)",
         "description_kn": "ಫೋನ್ ಆಪ್‌ನಂತೆ ಹೆಸರಿದೆ, ಆದರೆ ಇದು ವೇಷ ಧರಿಸಿದ ಪ್ರೋಗ್ರಾಂ.",
         "expected": "Dangerous"},
        {"id": "exe_safe", "kind": "exe", "file": "PhotoViewer_Setup.exe",
         "title": "PhotoViewer_Setup.exe",
         "description": "An ordinary signed installer, for comparison.",
         "title_kn": "PhotoViewer_Setup.exe",
         "description_kn": "ಹೋಲಿಕೆಗಾಗಿ ಸಹಿ ಇರುವ ಸಾಮಾನ್ಯ ಇನ್‌ಸ್ಟಾಲರ್.",
         "expected": "Safe"},
    ] + [{"kind": "qr", **{k: v for k, v in s.items() if k != "payload"}} for s in QR_SAMPLES] + SMS_SAMPLES
    (OUT / "samples.json").write_text(json.dumps({"harmless_demo_samples": True, "samples": samples},
                                                 indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(samples)} harmless demo samples to {OUT}")


if __name__ == "__main__":
    main()
