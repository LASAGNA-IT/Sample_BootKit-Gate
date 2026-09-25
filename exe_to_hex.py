#!/usr/bin/env python3
"""
exe_to_hex.py — converte un .exe in un header C con array esadecimale.

Uso:
    python exe_to_hex.py TuoFile.exe > payload.h
"""

import sys

def main() -> int:
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <file.exe>", file=sys.stderr)
        return 1

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Errore: {e}", file=sys.stderr)
        return 1

    print("/* Generato automaticamente da exe_to_hex.py — NON MODIFICARE */")
    print("#ifndef PAYLOAD_H")
    print("#define PAYLOAD_H\n")
    print("unsigned char payload_data[] = {")
    line = "    "
    for i, b in enumerate(data):
        token = f"0x{b:02X}, "
        if len(line) + len(token) > 78:
            print(line.rstrip())
            line = "    "
        line += token
    if line.strip():
        print(line.rstrip().rstrip(","))
    print("};\n")
    print(f"unsigned int payload_len = {len(data)}u;\n")
    print("#endif /* PAYLOAD_H */")
    return 0

if __name__ == "__main__":
    sys.exit(main())