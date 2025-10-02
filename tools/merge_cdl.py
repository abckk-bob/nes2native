#!/usr/bin/env python3
# tools/merge_cdl.py — OR-merge multiple .cdl files (byte-wise)
import sys

def main():
    if len(sys.argv) < 4:
        print("Usage: merge_cdl.py OUT.cdl IN1.cdl IN2.cdl [IN3.cdl ...]")
        sys.exit(1)
    out = sys.argv[1]
    ins = sys.argv[2:]
    data = None
    for path in ins:
        with open(path, "rb") as f:
            buf = f.read()
        if data is None:
            data = bytearray(buf)
        else:
            if len(buf) != len(data):
                raise SystemExit(f"Size mismatch: {path}")
            for i in range(len(data)):
                data[i] |= buf[i]
    with open(out, "wb") as f:
        f.write(data)
    print(f"[merge_cdl] wrote {out} from {len(ins)} inputs.")

if __name__ == "__main__":
    main()
