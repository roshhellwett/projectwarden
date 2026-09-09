"""Shared error helpers for CLI commands and the native host.

Every user-facing failure maps to a stable short code the user can quote in
support mail (zenithprojects@icloud.com) together with the base64 detail.
"""
import base64
import re
import sys

SUPPORT_EMAIL = "zenithprojects@icloud.com"

# Stable, greppable error codes.
ERR_WRONG_PASSWORD = "ZP-E001"
ERR_VAULT_MISSING = "ZP-E002"
ERR_CORRUPT_VAULT = "ZP-E003"
ERR_RECOVERY = "ZP-E004"
ERR_IMPORT_FILE = "ZP-E005"
ERR_HOST_UNREACHABLE = "ZP-E006"
ERR_NATIVE_LOCK_FAILED = "ZP-E007"


def make_error_code(exc: Exception | str) -> str:
    """Build a compact support code: stable prefix + base64 detail + version tag."""
    detail = str(exc) if isinstance(exc, str) is False else exc
    safe = re.sub(r"[^A-Za-z0-9 _.-]", "", str(detail))[:40]
    b64 = base64.b64encode(str(detail).encode("utf-8")).decode("ascii")[:60]
    py = f"py{sys.version_info.major}.{sys.version_info.minor}"
    return f"{py}|{safe}|{b64}"


def error_payload(exc: Exception | str, code: str) -> dict:
    """Native-host style error object with support info."""
    return {
        "error": str(exc),
        "errorCode": code,
        "errorDetail": make_error_code(exc),
        "support": SUPPORT_EMAIL,
    }
