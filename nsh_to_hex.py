#!/usr/bin/env python3
"""
nsh_to_hex.py — converte un file .nsh in un array C esadecimale.
Normalizza sempre le line endings a CRLF (\r\n).

Uso:
    python nsh_to_hex.py startup_default.nsh NSH_DEFAULT >> nsh_scripts.h
    python nsh_to_hex.py startup_custom.nsh  NSH_CUSTOM  >> nsh_scripts.h
"""

import sys

def main() -> int:
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <file.nsh> <nome_array>", file=sys.stderr)
        return 1

    path, name = sys.argv[1], sys.argv[2]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Errore: {e}", file=sys.stderr)
        return 1

    # Normalizza a CRLF
    data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

    print(f"/* {path} — {len(data)} byte */")
    print(f"static const unsigned char {name}[] = {{")
    line = "    "
    for b in data:
        tok = f"0x{b:02X}, "
        if len(line) + len(tok) > 78:
            print(line.rstrip())
            line = "    "
        line += tok
    if line.strip():
        print(line.rstrip().rstrip(","))
    print("};")
    print(f"static const unsigned int {name}_len = {len(data)}u;")
    print()
    return 0

if __name__ == "__main__":
    sys.exit(main())