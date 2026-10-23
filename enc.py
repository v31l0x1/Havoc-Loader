#!/usr/bin/env python3
import re
import struct
import sys
from pathlib import Path

KEY = "mysecretkey"


def maybe_parse_hex(raw: bytes) -> bytes:
    if b"0x" not in raw[:4096]:
        return raw
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    tokens = re.findall(r"0x([0-9A-Fa-f]{2})\b", text)
    if len(tokens) < 16:
        return raw
    return bytes(int(t, 16) for t in tokens)


def find_pe_offset(data: bytes) -> int:
    pos = 0
    while True:
        i = data.find(b"MZ", pos)
        if i < 0 or i + 0x40 > len(data):
            return -1
        e_lfanew = struct.unpack_from("<I", data, i + 0x3C)[0]
        if 0x40 <= e_lfanew <= 0x1000:
            pe = i + e_lfanew
            if pe + 4 <= len(data) and data[pe:pe + 4] == b"PE\0\0":
                return i
        pos = i + 1


def xor_bytes(data: bytes, key: str) -> bytes:
    k = key.encode("latin1")
    n = len(k)
    return bytes(b ^ k[i % n] for i, b in enumerate(data))


def rust_u8_array(name: str, data: bytes, per_line: int = 16) -> str:
    lines = [f"pub const {name}: &[u8] = &["]
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("];")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 1

    src = Path(argv[1])
    dst = Path(argv[2]) if len(argv) > 2 else Path("shellcode.rs")

    data = maybe_parse_hex(src.read_bytes())
    off = find_pe_offset(data)
    if off < 0:
        return 1

    pe = data[off:]
    cipher = xor_bytes(pe, KEY)
    key_bytes = KEY.encode("latin1")

    out = [
        rust_u8_array("SHELLCODE", cipher),
        "",
        rust_u8_array("KEY", key_bytes),
        "",
    ]
    dst.write_text("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))