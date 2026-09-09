#!/usr/bin/env python3
"""Zenith Passkeys - Chrome Web Store Zip Packager.

Packages the contents of extension/ directly into a zip archive ready for
upload to the Chrome Web Store Developer Dashboard.

Built and managed by Zenith Open Source Projects.
"""

import zipfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    ext_dir = root / "extension"
    manifest_path = ext_dir / "manifest.json"

    import json
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    version = manifest_data.get("version", "1.1.2")

    out_zip = root / f"zenith-passkeys-v{version}-webstore.zip"
    out_zip_latest = root / "zenith-passkeys-webstore.zip"

    print("=" * 60)
    print(f" Zenith Passkeys - Web Store Packager (v{version})")
    print("=" * 60)

    for target_path in [out_zip, out_zip_latest]:
        with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for file_path in sorted(ext_dir.rglob("*")):
                if file_path.is_file():
                    if file_path.name.startswith(".") or file_path.suffix in (".bak", ".tmp", ".pyc"):
                        continue
                    arcname = file_path.relative_to(ext_dir).as_posix()
                    zf.write(file_path, arcname)

    print(f"\n[+] Package created successfully:")
    print(f"    File: {out_zip.resolve()}")
    print(f"    Size: {out_zip.stat().st_size:,} bytes")
    print(f"    Also mirrored at: {out_zip_latest.name}")

    with zipfile.ZipFile(out_zip, "r") as zf:
        print(f"\n[*] Archive contents ({len(zf.infolist())} files):")
        for item in zf.infolist():
            print(f"    + {item.filename:<30} ({item.file_size:,} bytes)")

    print("\n[SUCCESS] Ready for upload at https://chrome.google.com/webstore/devconsole")


if __name__ == "__main__":
    main()
