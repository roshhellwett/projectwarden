"""Cross-process vault lock signaling.

The CLI and the native host are separate OS processes. The native host
polls a sentinel file in the vault directory; when the sentinel exists it
wipes its in-memory MEK/payload and deletes the sentinel. This makes the
CLI 'lock' command real instead of a placebo (audit F-021).

Lock semantics: create sentinel -> host notices within its poll interval
and locks -> sentinel removed by host. If no host is running, the sentinel
is simply cleaned up by the next host start or by this module.
"""
from pathlib import Path

from ..core.paths import get_vault_dir

SENTINEL_NAME = "lock-requested"
# How the host reports back that it honored the lock (cleared + wrote this).
SENTINEL_ACK = "lock-ack"
SENTINEL_CHECK_INTERVAL = 1.0  # seconds, host-side poll


def get_sentinel_dir() -> Path:
    d = get_vault_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def request_lock() -> bool:
    """Ask every running native host to lock. Returns True if the sentinel was placed."""
    d = get_sentinel_dir()
    # Clear any stale ack from a previous lock so read_lock_ack() reflects THIS request.
    try:
        (d / SENTINEL_ACK).unlink(missing_ok=True)
    except OSError:
        pass
    sentinel = d / SENTINEL_NAME
    try:
        sentinel.write_text("lock")
        return True
    except OSError:
        return False


def consume_lock_request() -> bool:
    """Host-side: True exactly once when a lock was requested. Removes the sentinel."""
    sentinel = get_sentinel_dir() / SENTINEL_NAME
    try:
        if sentinel.exists():
            sentinel.unlink()
            return True
    except OSError:
        return False
    return False


def write_lock_ack() -> None:
    """Host-side: record that the lock was honored (diagnostics for the CLI)."""
    try:
        (get_sentinel_dir() / SENTINEL_ACK).write_text("locked")
    except OSError:
        pass


def read_lock_ack() -> bool:
    return (get_sentinel_dir() / SENTINEL_ACK).exists()


SENTINEL_CHECK_RESULTS = read_lock_ack  # re-export convenience
