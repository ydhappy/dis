from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{6,}")
MZ_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"


def analyze_memory_dump(path: str | Path, max_strings: int = 200, max_regions: int = 200) -> dict[str, Any]:
    dump_path = Path(path)
    data = dump_path.read_bytes()
    mz_offsets = find_signature_offsets(data, MZ_SIGNATURE, max_hits=500)
    pe_offsets = find_signature_offsets(data, PE_SIGNATURE, max_hits=500)
    strings = extract_printable_strings(data, max_strings=max_strings)
    entropy_regions = scan_high_entropy_regions(data, max_regions=max_regions)

    return {
        "path": str(dump_path),
        "size": len(data),
        "mz_signature_count": len(mz_offsets),
        "mz_offsets": mz_offsets,
        "pe_signature_count": len(pe_offsets),
        "pe_offsets": pe_offsets,
        "string_count": len(strings),
        "strings": strings,
        "high_entropy_region_count": len(entropy_regions),
        "high_entropy_regions": entropy_regions,
        "note": "Offline dump analysis only. This tool does not attach to or dump live process memory.",
    }


def find_signature_offsets(data: bytes, signature: bytes, max_hits: int) -> list[str]:
    offsets: list[str] = []
    start = 0
    while True:
        index = data.find(signature, start)
        if index == -1:
            break
        offsets.append(f"0x{index:X}")
        start = index + 1
        if len(offsets) >= max_hits:
            break
    return offsets


def extract_printable_strings(data: bytes, max_strings: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in PRINTABLE_RE.finditer(data):
        value = match.group(0).decode("utf-8", errors="replace")
        results.append(
            {
                "offset": f"0x{match.start():X}",
                "length": len(match.group(0)),
                "value": value[:300],
            }
        )
        if len(results) >= max_strings:
            break
    return results


def scan_high_entropy_regions(
    data: bytes,
    window_size: int = 4096,
    threshold: float = 7.4,
    max_regions: int = 200,
) -> list[dict[str, Any]]:
    regions: list[dict[str, Any]] = []
    if not data:
        return regions
    for offset in range(0, len(data), window_size):
        chunk = data[offset : offset + window_size]
        if len(chunk) < 512:
            continue
        entropy = calculate_entropy(chunk)
        if entropy >= threshold:
            regions.append({"offset": f"0x{offset:X}", "size": len(chunk), "entropy": entropy})
        if len(regions) >= max_regions:
            break
    return regions


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)
