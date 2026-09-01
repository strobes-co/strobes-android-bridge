# patch_apk.py

Patches a target Android APK to trust the Strobes Bridge MITM CA on a
**non-rooted** device, so traffic interception works even for apps that
target API 24+ (which ignore user-installed CA certs by default) or ship
their own certificate pinning.

On a rooted device the bridge needs none of this — root lets it install the
CA into the system trust store directly, and every app trusts it. This
script exists for the case root isn't available and the target app itself
is the thing refusing to trust our CA.

## What it does

1. Decompiles the APK with `apktool`.
2. Finds (or creates) its Network Security Config and:
   - Adds `<certificates src="user"/>` to every `base-config`/`domain-config`
     trust-anchors block that's missing it.
   - Strips any `<pin-set>` blocks (cert pinning survives a trust-anchor
     change otherwise — the pinned domain would still reject our CA).
   - Adds `android:networkSecurityConfig` to `<application>` if the app
     didn't already have one.
3. Detects `targetSdkVersion < 24` and skips patching entirely (those apps
   already trust user certs by default — nothing to do).
4. Rebuilds, zipaligns, and signs with a stable local debug key (kept at
   `~/.strobes-bridge/patch-apk-debug.keystore` so repeated patches of the
   same app stay mutually upgradable).

## What it deliberately does NOT do

- Bypass in-code certificate pinning (a hardcoded `CertificatePinner`, a
  custom `TrustManager`). Only NSC-declared pinning is removed. In-code
  pinning needs a runtime hook (Frida/objection) — a different technique,
  not wired in here.
- Handle `.aab` App Bundles, or apps split across multiple install-time
  APKs beyond patching the base APK.
- Touch dex/smali. Resource/manifest-only changes are the lowest-risk patch
  that achieves cert trust, and won't break obfuscated app logic the way
  bytecode patching can.

## Requirements

- `apktool` on PATH (`brew install apktool`)
- Android SDK build-tools (`zipalign`, `apksigner`) — set `ANDROID_HOME` or
  pass `--build-tools /path/to/build-tools/<version>`
- `keytool` (ships with any JDK)

## Usage

```bash
# See what would be patched without touching anything:
python3 patch_apk.py target.apk --report-only

# Patch it:
python3 patch_apk.py target.apk -o target-patched.apk

# Patch and reinstall immediately (uninstalls the original first — a
# different signing key means it can't be an in-place upgrade, so this
# wipes the app's local data):
python3 patch_apk.py target.apk --install --device emulator-5554
```

The CA cert itself isn't embedded by this script — the device still needs
to trust it separately via the bridge app's own onboarding wizard (which
now offers "Download certificate" → "Install certificate" for exactly this,
see `OnboardingActivity`). `--ca-cert` is accepted for future wiring but
isn't required for the patch to work.

## Status

Verified against two real local test APKs end-to-end (decompile → patch →
rebuild → zipalign → sign → install → launch, no crash): one with an
already-permissive NSC (correctly detected as "already OK", no-op), one
with a system-only `base-config` and a partially-permissive `domain-config`
(correctly patched only what needed it).

**Not yet wired into the agent's tool belt** — this is a standalone CLI
script in this repo, not a registered agent tool in the backend. Wiring
"agent detects no root → runs this → reinstalls → resumes testing" into the
actual pentest agent loop is a separate step in the backend repo, out of
scope here per the standing "don't touch backend code" constraint on this
session.
