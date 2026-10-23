# Demo samples

Run from the repo root:

```bash
python samples/make_demo_samples.py
```

This writes harmless samples to `samples/out/` and a `samples.json` index that the
website reads. All samples are created by the script itself. **Never use real malware
for demos.**

## Why the APKs are safe

`make_demo_samples.py` builds each APK from scratch:

- `AndroidManifest.xml`: a binary (AXML) manifest declaring the app name, package and
  permissions.
- `classes.dex`: a valid DEX file that contains **only a string table**. There are no
  classes, methods or bytecode, so there is nothing that can run.
- `META-INF/`: a v1 JAR signature. The fake app uses an "Android Debug" certificate on
  purpose, because that is a real scam signal.

The fake app's strings include `https://api.telegram.org/botDEMO_NOT_REAL/sendMessage`,
a URL that does not work.

## Building a test APK in Android Studio instead (optional)

If a teammate wants a "real" build for the demo:

1. New project, Empty Views Activity, app name **RTO Challan**.
2. In `AndroidManifest.xml` add `READ_SMS`, `RECEIVE_SMS` and a `<service>` with
   `android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"`.
3. Add `<string name="endpoint">https://api.telegram.org/botDEMO_NOT_REAL</string>`
   to `strings.xml`.
4. Build a debug APK (Build > Build APK). Do not install it on a phone.

ScamShield should rate it **Dangerous**. Compare it with any legitimate open-source APK
for a **Safe** result.
