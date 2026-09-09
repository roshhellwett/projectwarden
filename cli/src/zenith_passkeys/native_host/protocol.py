import json
import struct
import sys

MAX_MESSAGE_SIZE = 1024 * 1024

if sys.platform == "win32":
    import msvcrt
    import os
    try:
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    except Exception:  # noqa: BLE001, S110 - stdio mode switch is best-effort
        pass

def read_message() -> dict | None:
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None
    length = struct.unpack("@I", raw_length)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length}")
    data = sys.stdin.buffer.read(length)
    if len(data) < length:
        return None
    return json.loads(data.decode("utf-8"))

def send_message(msg: dict) -> None:
    encoded = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("@I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
