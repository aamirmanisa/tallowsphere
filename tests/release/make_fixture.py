#!/usr/bin/env python3
"""Build a local fixture "release" for installer E2E tests.

Generates, in --out:
    <archive>                  fixture archive (contains `tallow` / `tallow.exe`)
    <archive>.sha256           checksum sidecar (release.yml format)
    <archive>.tallow.sig       Ed25519 signature over the sha256 hex-string bytes
    <archive>.tallow.pub       raw 32-byte public key (throwaway, per run)
    fixture_pub.b64            base64 of the public key (for TALLOW_PUBKEY env)
    latest.json                GitHub-shaped releases/latest payload whose asset
                               URLs point at http://127.0.0.1:<port>/... (serve
                               this directory and point the installers'
                               TALLOW_RELEASE_API_URL at it)

Signing uses python `cryptography` when available and falls back to the
`openssl` CLI (both emit the same raw Ed25519 signature over the sha256
hex-string bytes that release.yml emits and the installers verify).

The signing key is a THROWAWAY key generated per run — never reuse it for a
real release. Fixture archives embed a harmless stand-in binary:
  * linux:   a `tallow` shell script that echoes its arguments
  * windows: a copy of the host's `hostname.exe` (works on windows-latest;
             pass --exe-src for other hosts, e.g. /bin/true on Linux)
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def arch_name():
    m = platform.machine().lower()
    return {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(m, m)


def sign_sha256_hex(hexd):
    """Return (pub_raw[32], sig[64]) for the sha256 hex string — Ed25519."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.sign(hexd.encode("ascii"))
    except ImportError:
        pass
    keydir = tempfile.mkdtemp(prefix="tallow-fixture-key-")
    try:
        key = os.path.join(keydir, "key.pem")
        pub_der = os.path.join(keydir, "pub.der")
        msg = os.path.join(keydir, "msg")
        sig = os.path.join(keydir, "sig")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER", "-out", pub_der],
                       check=True, capture_output=True)
        with open(msg, "w") as f:
            f.write(hexd)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msg, "-out", sig],
                       check=True, capture_output=True)
        return open(pub_der, "rb").read()[-32:], open(sig, "rb").read()
    finally:
        shutil.rmtree(keydir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--platform", choices=["linux", "windows"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--exe-src", default=None,
                    help="binary to embed as tallow.exe (windows fixture); "
                         "default: %%SystemRoot%%\\System32\\hostname.exe on Windows, /bin/true elsewhere")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    if args.platform == "windows":
        archive = "tallow-windows-x86_64.zip"
        inner = "tallow.exe"
        exe_src = args.exe_src
        if not exe_src:
            exe_src = (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "hostname.exe")
                       if os.name == "nt" else "/bin/true")
        if not os.path.isfile(exe_src):
            sys.exit(f"fixture exe source not found: {exe_src}")
    else:
        archive = f"tallow-linux-{arch_name()}-musl.tar.gz"
        inner = "tallow"
        exe_src = None
    base = f"http://127.0.0.1:{args.port}"

    # ── fixture payload archive ──────────────────────────────────────────
    stage = tempfile.mkdtemp(prefix="tallow-fixture-stage-")
    p = os.path.join(stage, inner)
    if args.platform == "linux":
        with open(p, "w") as f:
            f.write('#!/bin/sh\necho "tallow 1.0.0-fixture ($*)"\nexit 0\n')
        os.chmod(p, 0o755)
        with tarfile.open(os.path.join(out, archive), "w:gz") as tf:
            tf.add(p, arcname=inner)
    else:
        if not exe_src:
            sys.exit("windows fixture requires an exe source")
        shutil.copy(exe_src, p)
        with zipfile.ZipFile(os.path.join(out, archive), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(p, arcname=inner)
    shutil.rmtree(stage, ignore_errors=True)

    # ── sha256 sidecar + Ed25519 signature over the hex-string bytes ────
    hexd = hashlib.sha256(open(os.path.join(out, archive), "rb").read()).hexdigest()
    with open(os.path.join(out, f"{archive}.sha256"), "w") as f:
        f.write(f"{hexd}  {archive}\n")
    pub_raw, sig = sign_sha256_hex(hexd)
    assert len(pub_raw) == 32 and len(sig) == 64, "unexpected Ed25519 key/signature size"
    with open(os.path.join(out, "fixture_pub.b64"), "w") as f:
        f.write(base64.b64encode(pub_raw).decode() + "\n")
    with open(os.path.join(out, f"{archive}.tallow.pub"), "wb") as f:
        f.write(pub_raw)  # raw, exactly what release.yml writes
    with open(os.path.join(out, f"{archive}.tallow.sig"), "wb") as f:
        f.write(sig)

    # ── GitHub-shaped latest.json (sidecar + decoy assets for F-01) ─────
    def asset(name):
        return {"name": name, "browser_download_url": f"{base}/{name}"}

    decoys = (["tallow-linux-x86_64-musl.tar.gz", "tallow-linux-aarch64-musl.tar.gz"]
              if args.platform == "windows" else
              ["tallow-windows-x86_64.zip", "tallow-linux-x86_64-musl.tar.gz" if arch_name() != "x86_64"
               else "tallow-linux-aarch64-musl.tar.gz"])
    assets = [asset(archive), asset(f"{archive}.tallow.sig"), asset(f"{archive}.sha256"),
              asset(f"{archive}.tallow.pub"), asset(f"{archive}.sig")]
    for name in decoys:
        if name != archive:
            assets.append(asset(name))
    assets.append(asset("README.md"))
    with open(os.path.join(out, "latest.json"), "w") as f:
        json.dump({"tag_name": "v1.0-fixture", "assets": assets}, f, indent=2)

    print(json.dumps({"archive": archive, "out": out, "base": base}))


if __name__ == "__main__":
    sys.exit(main())
