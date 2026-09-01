#!/usr/bin/env python3
"""
Patch an Android APK so its traffic trusts the Strobes Bridge MITM CA on a
non-rooted device — the "APK-side" complement to the bridge app's own
non-root fallback. Root gives the bridge every capability without touching
the target app; without root, the one thing nothing else can substitute for
is a target app that itself refuses to trust a user-installed CA cert
(the Android N+ default for any app targeting API 24+). This script closes
that specific gap by patching the target's own Network Security Config
(NSC) to trust user certs, using the same static-patching technique as the
well-known `apk-mitm` tool — decompile with apktool, edit the NSC/manifest,
recompile, zipalign, re-sign with a stable local debug key.

What this does NOT do (by design, not oversight):
  - Bypass in-code certificate pinning (e.g. a hardcoded OkHttp
    CertificatePinner, or a custom TrustManager) — only NSC-declared
    <pin-set> pinning is removed. In-code pinning needs a runtime hook
    (Frida/objection), which is a different technique with a different risk
    profile; wire that in separately if a target needs it.
  - Handle Android App Bundles (.aab) or multi-APK split installs beyond
    patching the base APK — flagged explicitly, not silently mishandled.
  - Touch dex/smali at all — resource/manifest-only changes are the
    lowest-risk patch that achieves cert trust, and won't break obfuscated
    app logic the way bytecode patching can.

Requires on PATH: apktool, and Android SDK build-tools (zipalign, apksigner)
— point ANDROID_HOME/ANDROID_SDK_ROOT at your SDK, or pass --build-tools.
Also needs `keytool` (ships with any JDK).

Typical use:
    python3 patch_apk.py target.apk --ca-cert strobes-bridge-ca.crt

    # Inspect only, no rebuild — decide whether patching is even needed:
    python3 patch_apk.py target.apk --report-only

    # Patch and immediately reinstall over adb (uninstalls the original
    # first — a different signature means it can't be an in-place upgrade):
    python3 patch_apk.py target.apk --ca-cert strobes-bridge-ca.crt --install

The CA cert to trust is the bridge's own MITM CA — pull it from a paired
device's Downloads folder (the bridge app's onboarding wizard saves it
there) or from wherever your bridge instance exports it, then pass its path
via --ca-cert.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)


def android_attr(tag: str) -> str:
    return f"{{{ANDROID_NS}}}{tag}"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


def find_sdk_tool(name: str, build_tools_override: str | None) -> str:
    """Locates an Android SDK build-tools binary — tries an explicit
    override first, then the newest installed build-tools version under
    ANDROID_HOME/ANDROID_SDK_ROOT, then falls back to PATH."""
    if build_tools_override:
        candidate = Path(build_tools_override) / name
        if candidate.exists():
            return str(candidate)
        raise SystemExit(f"{name} not found under --build-tools {build_tools_override}")

    import os

    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        build_tools_dir = Path(sdk_root) / "build-tools"
        if build_tools_dir.is_dir():
            versions = sorted(
                (d for d in build_tools_dir.iterdir() if d.is_dir()),
                key=lambda d: d.name,
                reverse=True,
            )
            for v in versions:
                candidate = v / name
                if candidate.exists():
                    return str(candidate)

    on_path = shutil.which(name)
    if on_path:
        return on_path
    raise SystemExit(
        f"Could not find '{name}'. Set ANDROID_HOME/ANDROID_SDK_ROOT, or pass --build-tools "
        f"<path to a build-tools/<version> dir>."
    )


@dataclass
class PatchReport:
    package: str = ""
    target_sdk: int | None = None
    needed_patch: bool = True
    reason: str = ""
    nsc_existing: bool = False
    pin_sets_removed: int = 0
    domain_configs_patched: int = 0
    domain_configs_already_ok: int = 0
    base_config_created: bool = False
    base_config_modified: bool = False
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Package:            {self.package or '(unknown)'}",
            f"Target SDK:         {self.target_sdk if self.target_sdk is not None else '(unknown)'}",
        ]
        if not self.needed_patch:
            lines.append(f"Patch needed:       NO — {self.reason}")
        else:
            lines.append("Patch needed:       yes")
            lines.append(f"Existing NSC file:  {'yes' if self.nsc_existing else 'no (created one)'}")
            if self.base_config_created:
                base_line = "created (none existed)"
            elif self.base_config_modified:
                base_line = "modified (added user cert trust)"
            else:
                base_line = "already trusted user certs, left as-is"
            lines.append(f"base-config:        {base_line}")
            lines.append(
                f"domain-configs:     {self.domain_configs_patched} patched, "
                f"{self.domain_configs_already_ok} already OK",
            )
            lines.append(f"<pin-set> stripped: {self.pin_sets_removed}")
        for w in self.warnings:
            lines.append(f"WARNING: {w}")
        return "\n".join(lines)


def parse_target_sdk(work_dir: Path) -> int | None:
    """apktool (in its default aapt2 mode) pulls targetSdkVersion out of the
    decompiled AndroidManifest.xml entirely and records it only in
    apktool.yml's sdkInfo block — so that's the primary source. Falls back
    to a <uses-sdk> element in the manifest for older apktool output that
    still inlines it."""
    yml_path = work_dir / "apktool.yml"
    if yml_path.exists():
        in_sdk_info = False
        for line in yml_path.read_text(encoding="utf-8").splitlines():
            if line.strip() == "sdkInfo:":
                in_sdk_info = True
                continue
            if in_sdk_info:
                if line.startswith((" ", "\t")):
                    stripped = line.strip()
                    if stripped.startswith("targetSdkVersion:"):
                        try:
                            return int(stripped.split(":", 1)[1].strip())
                        except ValueError:
                            return None
                else:
                    break  # dedented past sdkInfo: without finding the key

    manifest_path = work_dir / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    uses_sdk = tree.getroot().find("uses-sdk")
    if uses_sdk is None:
        return None
    val = uses_sdk.get(android_attr("targetSdkVersion")) or uses_sdk.get(android_attr("minSdkVersion"))
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def ensure_user_trust_anchor(trust_anchors: ET.Element) -> bool:
    """Adds <certificates src="user"/> to [trust_anchors] if not already
    present. Returns True if it made a change."""
    for cert in trust_anchors.findall("certificates"):
        if cert.get("src") == "user":
            return False
    ET.SubElement(trust_anchors, "certificates", {"src": "user"})
    return True


def patch_config_block(block: ET.Element, report: PatchReport) -> bool:
    """Patches one <base-config> or <domain-config> element in place: makes
    sure it trusts user certs, and strips any <pin-set> (pinning survives
    trust-anchor changes otherwise — the domain would still reject our CA).
    Returns True if the block was actually modified (already-permissive
    blocks are left untouched and don't count as "patched")."""
    changed = False
    trust_anchors = block.find("trust-anchors")
    if trust_anchors is None:
        trust_anchors = ET.SubElement(block, "trust-anchors")
        # No pre-existing anchors means the platform default (system-only)
        # applied — make it explicit so both system and user certs are
        # trusted, not just user (some requests may rely on system CAs too).
        ET.SubElement(trust_anchors, "certificates", {"src": "system"})
        ET.SubElement(trust_anchors, "certificates", {"src": "user"})
        changed = True
    else:
        changed |= ensure_user_trust_anchor(trust_anchors)

    pin_sets = block.findall("pin-set")
    for pin_set in pin_sets:
        block.remove(pin_set)
    report.pin_sets_removed += len(pin_sets)
    changed |= len(pin_sets) > 0
    return changed


def patch_network_security_config(nsc_path: Path, report: PatchReport) -> None:
    tree = ET.parse(nsc_path)
    root = tree.getroot()

    base_config = root.find("base-config")
    if base_config is None:
        base_config = ET.Element("base-config")
        root.insert(0, base_config)
        report.base_config_created = True
        patch_config_block(base_config, report)
    else:
        report.base_config_modified = patch_config_block(base_config, report)

    for domain_config in root.findall("domain-config"):
        if patch_config_block(domain_config, report):
            report.domain_configs_patched += 1
        else:
            report.domain_configs_already_ok += 1

    tree.write(nsc_path, encoding="utf-8", xml_declaration=True)


def build_fresh_network_security_config(nsc_path: Path) -> None:
    nsc_path.parent.mkdir(parents=True, exist_ok=True)
    nsc_path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<network-security-config>\n"
        "    <base-config>\n"
        "        <trust-anchors>\n"
        '            <certificates src="system" />\n'
        '            <certificates src="user" />\n'
        "        </trust-anchors>\n"
        "    </base-config>\n"
        "</network-security-config>\n",
        encoding="utf-8",
    )


def patch_manifest(manifest_path: Path, report: PatchReport) -> Path:
    """Returns the resource-relative NSC path this manifest now points at
    (e.g. "res/xml/network_security_config.xml"), creating the attribute
    and/or the file if the app didn't already have one."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    report.package = root.get("package", "")

    application = root.find("application")
    if application is None:
        raise SystemExit("AndroidManifest.xml has no <application> element — unexpected APK shape, aborting.")

    existing = application.get(android_attr("networkSecurityConfig"))
    if existing:
        report.nsc_existing = True
        if not existing.startswith("@xml/"):
            report.warnings.append(
                f"networkSecurityConfig='{existing}' isn't a simple @xml/ resource — "
                "can't safely locate the file to patch. Skipping NSC edit; manifest attribute left as-is.",
            )
            return existing
        resource_name = existing[len("@xml/"):]
        return f"res/xml/{resource_name}.xml"

    application.set(android_attr("networkSecurityConfig"), "@xml/network_security_config")
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    return "res/xml/network_security_config.xml"


def decompile(apktool: str, apk_path: Path, out_dir: Path) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    run([apktool, "d", str(apk_path), "-o", str(out_dir), "-f"])


def rebuild(apktool: str, work_dir: Path, out_apk: Path) -> None:
    run([apktool, "b", str(work_dir), "-o", str(out_apk)])


def zipalign(zipalign_bin: str, in_apk: Path, out_apk: Path) -> None:
    run([zipalign_bin, "-f", "-p", "4", str(in_apk), str(out_apk)])


def ensure_debug_keystore(keytool_bin: str, keystore_path: Path) -> None:
    """A STABLE, reused-across-runs debug key — re-signing the same package
    with a fresh random key every run would make each patched build
    mutually un-upgradable (Android refuses to install over a package with
    a different signing key), forcing an uninstall between every re-patch."""
    if keystore_path.exists():
        return
    keystore_path.parent.mkdir(parents=True, exist_ok=True)
    run([
        keytool_bin, "-genkeypair", "-v",
        "-keystore", str(keystore_path),
        "-alias", "strobes-patch",
        "-storepass", "strobes-patch",
        "-keypass", "strobes-patch",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Strobes Bridge APK Patcher, O=Strobes, C=US",
    ])


def sign(apksigner_bin: str, keystore_path: Path, apk_path: Path) -> None:
    run([
        apksigner_bin, "sign",
        "--ks", str(keystore_path),
        "--ks-pass", "pass:strobes-patch",
        "--key-pass", "pass:strobes-patch",
        "--ks-key-alias", "strobes-patch",
        str(apk_path),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("apk", type=Path, help="Path to the target .apk (base APK — see limitations in the module docstring)")
    parser.add_argument("--ca-cert", type=Path, help="Path to the Strobes Bridge CA cert (only needed to hand off to --install's on-device trust step; patching itself doesn't embed the cert)")
    parser.add_argument("-o", "--output", type=Path, help="Output path for the patched APK (default: <name>-strobes-patched.apk next to the input)")
    parser.add_argument("--work-dir", type=Path, help="Decompile working directory (default: a temp dir next to the output, kept for inspection)")
    parser.add_argument("--build-tools", help="Path to a specific Android SDK build-tools/<version> directory (default: auto-detect newest under ANDROID_HOME)")
    parser.add_argument("--keystore", type=Path, default=Path.home() / ".strobes-bridge" / "patch-apk-debug.keystore", help="Path to the stable signing keystore (created on first use)")
    parser.add_argument("--report-only", action="store_true", help="Decompile and analyze only — report what would be patched, don't rebuild/sign")
    parser.add_argument("--install", action="store_true", help="After patching, adb-uninstall the original package and install the patched APK (DESTRUCTIVE: wipes the app's data — see the module docstring)")
    parser.add_argument("--device", help="adb -s <device> serial to target for --install")
    args = parser.parse_args()

    if not args.apk.exists():
        raise SystemExit(f"APK not found: {args.apk}")
    if args.apk.suffix == ".aab":
        raise SystemExit(
            "This is an Android App Bundle (.aab), not an installable APK — "
            "build/extract a device APK from it first (e.g. `bundletool build-apks`), "
            "this script doesn't handle bundles directly.",
        )

    apktool_bin = shutil.which("apktool")
    if not apktool_bin:
        raise SystemExit("apktool not found on PATH (brew install apktool, or see https://apktool.org).")
    keytool_bin = shutil.which("keytool")
    if not keytool_bin:
        raise SystemExit("keytool not found on PATH (ships with any JDK).")

    output = args.output or args.apk.with_name(args.apk.stem + "-strobes-patched.apk")
    work_dir = args.work_dir or args.apk.with_name(args.apk.stem + "-strobes-work")

    report = PatchReport()

    print(f"Decompiling {args.apk} ...")
    decompile(apktool_bin, args.apk, work_dir)

    manifest_path = work_dir / "AndroidManifest.xml"
    report.target_sdk = parse_target_sdk(work_dir)

    if report.target_sdk is not None and report.target_sdk < 24:
        report.needed_patch = False
        report.reason = (
            f"targetSdkVersion {report.target_sdk} < 24 — this app trusts user-installed CA certs "
            "by default on Android's own terms, no manifest/NSC patch required. Just install the "
            "original APK and trust the Strobes CA on the device as usual."
        )
        report.package = ET.parse(manifest_path).getroot().get("package", "")
        print("\n" + report.summary())
        if not args.report_only:
            print("\nNo patch applied — copying the original APK through unchanged.")
            shutil.copy(args.apk, output)
            print(f"Output: {output}")
        return

    nsc_relative = patch_manifest(manifest_path, report)
    nsc_path = work_dir / nsc_relative

    if nsc_path.exists():
        patch_network_security_config(nsc_path, report)
    else:
        if report.nsc_existing:
            report.warnings.append(
                f"Manifest points at {nsc_relative} but that file doesn't exist in the decompiled "
                "APK — creating a fresh one instead (the reference may have been to a resource "
                "apktool couldn't resolve by name; check --report-only output before trusting this).",
            )
        build_fresh_network_security_config(nsc_path)

    print("\n" + report.summary())

    if args.report_only:
        print(f"\n--report-only: decompiled sources left at {work_dir} for inspection, no rebuild performed.")
        return

    unsigned_apk = work_dir.with_name(work_dir.name + "-unsigned.apk")
    aligned_apk = work_dir.with_name(work_dir.name + "-aligned.apk")

    print(f"\nRebuilding ...")
    rebuild(apktool_bin, work_dir, unsigned_apk)

    zipalign_bin = find_sdk_tool("zipalign", args.build_tools)
    print("Zipaligning ...")
    zipalign(zipalign_bin, unsigned_apk, aligned_apk)

    apksigner_bin = find_sdk_tool("apksigner", args.build_tools)
    print("Signing ...")
    ensure_debug_keystore(keytool_bin, args.keystore)
    shutil.copy(aligned_apk, output)
    sign(apksigner_bin, args.keystore, output)

    unsigned_apk.unlink(missing_ok=True)
    aligned_apk.unlink(missing_ok=True)

    print(f"\nPatched APK: {output}")
    print(
        "NOTE: this is signed with a local Strobes debug key, not the original developer's key — "
        "installing it requires uninstalling any existing copy of the app first (different "
        "signature = not an in-place upgrade), which wipes that app's local data.",
    )

    if args.install:
        install(output, report.package, args.device)


def install(apk_path: Path, package: str, device: str | None) -> None:
    adb = ["adb"] + (["-s", device] if device else [])
    print(f"\nUninstalling existing {package} (if present) ...")
    subprocess.run(adb + ["uninstall", package], check=False)
    print(f"Installing {apk_path} ...")
    run(adb + ["install", str(apk_path)])
    print("Installed. Traffic from this app should now be interceptable once the Strobes Bridge proxy is running and its CA is trusted on-device.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"\nCommand failed (exit {e.returncode}): {e}", file=sys.stderr)
        sys.exit(1)
