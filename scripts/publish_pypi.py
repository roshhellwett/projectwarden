#!/usr/bin/env python3
"""Zenith Passkeys - PyPI Release & Distribution Tool.

Builds sdist and universal wheel distributions, validates package metadata,
and publishes the package to PyPI (https://pypi.org/project/zenithpasskeys/).

Built and managed by Zenith Open Source Projects.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Build and publish zenithpasskeys to PyPI.")
    parser.add_argument("--token", help="PyPI API token (pypi-...). If omitted, reads from TWINE_PASSWORD or prompts.")
    parser.add_argument("--dry-run", action="store_true", help="Build and validate package without uploading to PyPI.")
    parser.add_argument("--skip-build", action="store_true", help="Skip build step and upload existing dist/ artifacts.")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    cli_dir = root_dir / "cli"
    dist_dir = cli_dir / "dist"

    print("=" * 65)
    print(" Zenith Passkeys - PyPI Release Automation")
    print(" Built and managed by Zenith Open Source Projects")
    print("=" * 65)

    token = args.token or os.environ.get("TWINE_PASSWORD") or os.environ.get("PYPI_API_TOKEN")

    if not args.skip_build:
        if dist_dir.exists():
            print("\n[*] Cleaning old build artifacts in cli/dist/...")
            shutil.rmtree(dist_dir)
        dist_dir.mkdir(parents=True, exist_ok=True)

        print("\n[*] Building source distribution and wheel with 'python -m build'...")
        cmd_build = [sys.executable, "-m", "build", str(cli_dir), "--outdir", str(dist_dir)]
        res_build = subprocess.run(cmd_build, cwd=root_dir)
        if res_build.returncode != 0:
            print("[-] Build failed.", file=sys.stderr)
            sys.exit(res_build.returncode)

    dist_files = list(dist_dir.glob("*"))
    if not dist_files:
        print(f"[-] No distribution files found in {dist_dir}", file=sys.stderr)
        sys.exit(1)

    print("\n[*] Built artifacts:")
    for f in dist_files:
        print(f"    + {f.name} ({f.stat().st_size:,} bytes)")

    print("\n[*] Validating package distribution with 'twine check'...")
    cmd_check = [sys.executable, "-m", "twine", "check", *[str(f) for f in dist_files]]
    res_check = subprocess.run(cmd_check)
    if res_check.returncode != 0:
        print("[-] Twine validation failed. Please fix package metadata before uploading.", file=sys.stderr)
        sys.exit(res_check.returncode)

    print("[+] All packages passed twine validation!")

    if args.dry_run:
        print("\n[SUCCESS] Dry-run complete. Package is 100% ready for PyPI publication.")
        return

    if not token:
        import getpass
        print("\n[!] No PyPI API token provided in arguments or environment.")
        token = getpass.getpass("Enter PyPI API Token (pypi-...): ").strip()

    if not token or not token.startswith("pypi-"):
        print("[-] Invalid PyPI token: tokens must start with 'pypi-'.", file=sys.stderr)
        sys.exit(1)

    print("\n[*] Uploading distribution artifacts to PyPI...")
    env = os.environ.copy()
    env["TWINE_USERNAME"] = "__token__"
    env["TWINE_PASSWORD"] = token

    cmd_upload = [
        sys.executable, "-m", "twine", "upload",
        "--non-interactive",
        *[str(f) for f in dist_files]
    ]

    res_upload = subprocess.run(cmd_upload, env=env)
    if res_upload.returncode != 0:
        print("[-] Twine upload failed.", file=sys.stderr)
        sys.exit(res_upload.returncode)

    print("\n" + "=" * 65)
    print(" [SUCCESS] Package Published to PyPI!")
    print("=" * 65)
    print("  PyPI URL:  https://pypi.org/project/zenithpasskeys/")
    print("  Install:   pip install zenithpasskeys")
    print("  Commands:  zenith-passkeys  (or zenithpasskeys)")
    print("=" * 65)

    # Verification polling on PyPI JSON API
    print("\n[*] Verifying live registration on PyPI...")
    for attempt in range(1, 6):
        try:
            url = "https://pypi.org/pypi/zenithpasskeys/json"
            req = urllib.request.Request(url, headers={"User-Agent": "zenith-release-bot"})
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    v = data.get("info", {}).get("version")
                    print(f"[+] Confirmed: zenithpasskeys v{v} is live on PyPI!")
                    break
        except Exception:
            time.sleep(2)
    else:
        print("[i] Package uploaded successfully. Index caching might take 1-2 minutes to reflect on PyPI.")


if __name__ == "__main__":
    main()
