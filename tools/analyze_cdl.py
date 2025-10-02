#!/usr/bin/env python3
# tools/analyze_cdl.py — CDL統計生成スクリプト

import sys
import json
from pathlib import Path

# CDL bit masks (FCEUX format)
CDL_CODE = 0x01  # Code executed
CDL_DATA = 0x02  # Data read
CDL_PCM_DATA = 0x04  # PCM audio data
# Additional flags may exist depending on emulator

def analyze_cdl(cdl_path):
    """Analyze CDL file and return statistics."""
    cdl_data = Path(cdl_path).read_bytes()

    total = len(cdl_data)
    code_count = 0
    data_count = 0
    both_count = 0
    untouched_count = 0

    for byte in cdl_data:
        is_code = bool(byte & CDL_CODE)
        is_data = bool(byte & CDL_DATA)

        if is_code and is_data:
            both_count += 1
        elif is_code:
            code_count += 1
        elif is_data:
            data_count += 1
        else:
            untouched_count += 1

    # Calculate coverage
    code_coverage = ((code_count + both_count) / total * 100) if total > 0 else 0
    data_coverage = ((data_count + both_count) / total * 100) if total > 0 else 0
    total_coverage = ((total - untouched_count) / total * 100) if total > 0 else 0

    return {
        "file": str(cdl_path),
        "total_bytes": total,
        "code_only": code_count,
        "data_only": data_count,
        "code_and_data": both_count,
        "untouched": untouched_count,
        "coverage": {
            "code_percent": round(code_coverage, 2),
            "data_percent": round(data_coverage, 2),
            "total_percent": round(total_coverage, 2)
        }
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_cdl.py <cdl_file> [output.json]", file=sys.stderr)
        print("", file=sys.stderr)
        print("Analyzes FCEUX CDL file and outputs statistics.", file=sys.stderr)
        print("If output.json is specified, writes JSON to that file.", file=sys.stderr)
        print("Otherwise, prints to stdout.", file=sys.stderr)
        sys.exit(1)

    cdl_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    if not Path(cdl_file).exists():
        print(f"Error: CDL file not found: {cdl_file}", file=sys.stderr)
        sys.exit(1)

    stats = analyze_cdl(cdl_file)

    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"[analyze_cdl] Statistics written to {output_file}")
    else:
        print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
