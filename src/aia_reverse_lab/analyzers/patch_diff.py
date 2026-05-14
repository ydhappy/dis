from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def analyze_binary_diff(original: str | Path, modified: str | Path, max_ranges: int = 200) -> dict[str, Any]:
    """Compare two authorized binary files and report changed byte ranges.

    This does not generate patches, loaders, cracks, or modified executables.
    """
    original_path = Path(original)
    modified_path = Path(modified)
    original_data = original_path.read_bytes()
    modified_data = modified_path.read_bytes()

    ranges = collect_changed_ranges(original_data, modified_data, max_ranges=max_ranges)
    return {
        "original_path": str(original_path),
        "modified_path": str(modified_path),
        "original_size": len(original_data),
        "modified_size": len(modified_data),
        "original_sha256": sha256_bytes(original_data),
        "modified_sha256": sha256_bytes(modified_data),
        "size_delta": len(modified_data) - len(original_data),
        "changed_range_count": len(ranges),
        "changed_ranges": ranges,
        "truncated": len(ranges) >= max_ranges,
    }


def collect_changed_ranges(original: bytes, modified: bytes, max_ranges: int) -> list[dict[str, Any]]:
    max_len = max(len(original), len(modified))
    ranges: list[dict[str, Any]] = []
    start: int | None = None

    for index in range(max_len):
        original_byte = original[index] if index < len(original) else None
        modified_byte = modified[index] if index < len(modified) else None
        changed = original_byte != modified_byte

        if changed and start is None:
            start = index
        elif not changed and start is not None:
            ranges.append(build_range(original, modified, start, index))
            start = None
            if len(ranges) >= max_ranges:
                return ranges

    if start is not None and len(ranges) < max_ranges:
        ranges.append(build_range(original, modified, start, max_len))

    return ranges


def build_range(original: bytes, modified: bytes, start: int, end: int) -> dict[str, Any]:
    original_slice = original[start:min(end, len(original))]
    modified_slice = modified[start:min(end, len(modified))]
    preview_len = 32
    return {
        "start_offset": f"0x{start:X}",
        "end_offset_exclusive": f"0x{end:X}",
        "length": end - start,
        "original_preview": original_slice[:preview_len].hex(" "),
        "modified_preview": modified_slice[:preview_len].hex(" "),
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
