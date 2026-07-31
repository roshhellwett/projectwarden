import os

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def generate_recovery_key() -> tuple[bytes, str]:
    raw = os.urandom(20)
    display = format_recovery_key(raw)
    return raw, display

def format_recovery_key(raw: bytes) -> str:
    value = int.from_bytes(raw, "big")
    chars = []
    for i in range(32):
        chars.append(ALPHABET[(value >> (5 * (31 - i))) & 0x1F])
    groups = ["".join(chars[i:i+4]) for i in range(0, 32, 4)]
    return "-".join(groups)

def parse_recovery_key(display: str) -> bytes:
    display = display.upper().replace("-", "").replace(" ", "")
    if len(display) != 32:
        raise ValueError(f"Recovery key must be 32 characters, got {len(display)}")
    value = 0
    for c in display:
        idx = ALPHABET.index(c)
        value = (value << 5) | idx
    return value.to_bytes(20, "big")
