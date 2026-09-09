#!/usr/bin/env python3
"""Zenith Passkeys - Chrome Web Store Extension Packager.

Validates the Manifest V3 browser extension and packages it into a clean,
production-ready ZIP archive for the Chrome Web Store Developer Dashboard.

Built and managed by Zenith Open Source Projects.
"""

import json
import os
import sys
import zipfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    ext_dir = root / "extension"
    dist_dir = root / "dist"
    manifest_path = ext_dir / "manifest.json"

    print("=" * 65)
    print(" Zenith Passkeys - Chrome Web Store Packager")
    print(" Built and managed by Zenith Open Source Projects")
    print("=" * 65)

    if not manifest_path.exists():
        print(f"[-] Error: manifest.json not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[-] Error parsing manifest.json: {e}", file=sys.stderr)
        sys.exit(1)

    version = manifest.get("version", "1.0.0")
    name = manifest.get("name", "Zenith Passkeys")
    print(f"\n[*] Validating {name} v{version}...")

    # Manifest V3 Sanity Checks
    if manifest.get("manifest_version") != 3:
        print("[-] Error: manifest_version must be 3 for modern Chrome Web Store.", file=sys.stderr)
        sys.exit(1)

    required_files = [
        "manifest.json",
        "background.js",
        "content-main.js",
        "content-isolated.js",
        "confirm.html",
        "confirm.js",
        "fallback-vault.js",
        "lib/cbor.js",
        "popup/popup.html",
        "popup/popup.js",
        "popup/popup.css",
        "dashboard/dashboard.html",
        "dashboard/dashboard.css",
        "dashboard/dashboard.js",
        "icons/icon-16.png",
        "icons/icon-32.png",
        "icons/icon-48.png",
        "icons/icon-128.png",
    ]

    missing = []
    for rel_path in required_files:
        fpath = ext_dir / rel_path
        if not fpath.exists():
            missing.append(rel_path)

    if missing:
        print(f"[-] Error: Missing required files: {missing}", file=sys.stderr)
        sys.exit(1)

    print("[+] All required extension files verified successfully.")

    # Create dist folder
    dist_dir.mkdir(parents=True, exist_ok=True)
    zip_filename = f"zenith-passkeys-v{version}.zip"
    zip_path = dist_dir / zip_filename

    # Files/folders to exclude from zip
    exclude_patterns = {".git", ".DS_Store", "Thumbs.db", "__pycache__", ".pytest_cache"}

    # Prepare clean manifest for Chrome Web Store (strip browser_specific_settings Firefox key)
    chrome_manifest = dict(manifest)
    if "browser_specific_settings" in chrome_manifest:
        del chrome_manifest["browser_specific_settings"]
    chrome_manifest_bytes = json.dumps(chrome_manifest, indent=2).encode("utf-8")

    total_uncompressed = 0
    file_count = 0

    print(f"\n[*] Packaging extension into {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file_path in ext_dir.rglob("*"):
            if file_path.is_file():
                if any(part in exclude_patterns for part in file_path.parts):
                    continue
                if file_path.suffix in (".pyc", ".tmp", ".bak"):
                    continue

                rel = file_path.relative_to(ext_dir)
                arcname = str(rel).replace("\\", "/")

                if rel.name == "manifest.json":
                    zipf.writestr(arcname, chrome_manifest_bytes)
                    size = len(chrome_manifest_bytes)
                else:
                    zipf.write(file_path, arcname=arcname)
                    size = file_path.stat().st_size

                total_uncompressed += size
                file_count += 1
                print(f"    + {str(rel):<35} ({size:>6,} bytes)")

    zip_size = zip_path.stat().st_size

    print("\n" + "=" * 65)
    print(" [SUCCESS] Chrome Web Store Package Created!")
    print("=" * 65)
    print(f"  Artifact Path:   {zip_path}")
    print(f"  Files Packaged:  {file_count}")
    print(f"  Unpacked Size:   {total_uncompressed:,} bytes")
    print(f"  ZIP File Size:   {zip_size:,} bytes")
    print("\nNext Steps for Chrome Web Store Dashboard:")
    print("  1. Go to: https://chrome.google.com/webstore/devconsole")
    print("  2. Click the '+ New Item' button in your dashboard.")
    print(f"  3. Drag & drop or upload: {zip_path}")
    print("  4. See docs/STORE_LISTING.md for ready-to-copy metadata and descriptions.")
    print("=" * 65)


if __name__ == "__main__":
    main()
