"""
Wrapper script for the native messaging host.
Provides debug logging when ZENITH_DEBUG environment variable is set.
"""
import sys
import os
import traceback


def get_log_path():
    """Get the debug log path using platformdirs."""
    try:
        from platformdirs import user_config_dir
        config_dir = user_config_dir("zenith-passkeys", ensure_exists=True)
        return os.path.join(config_dir, "host_debug.log")
    except Exception:
        return None


def log(msg):
    """Write a debug log message if ZENITH_DEBUG is set."""
    if not os.environ.get("ZENITH_DEBUG"):
        return
    log_path = get_log_path()
    if log_path:
        try:
            with open(log_path, "a") as f:
                f.write(msg + "\n")
        except Exception:
            pass


try:
    log("Starting host...")
    from zenith_passkeys.native_host.host import NativeHost
    host = NativeHost()
    log("Host initialized.")
    host.run()
except Exception as e:
    log("Fatal exception:\n" + traceback.format_exc())
