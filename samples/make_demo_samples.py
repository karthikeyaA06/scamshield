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
    ] + [{"kind": "qr", **{k: v for k, v in s.items() if k != "payload"}} for s in QR_SAMPLES]
    (OUT / "samples.json").write_text(json.dumps({"harmless_demo_samples": True, "samples": samples},
                                                 indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(samples)} harmless demo samples to {OUT}")


if __name__ == "__main__":
    main()
