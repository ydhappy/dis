from __future__ import annotations

import math
from pathlib import Path
from typing import Any


def view_binary_range(path: str | Path, offset: int = 0, length: int = 256, width: int = 16) -> dict[str, Any]:
    file_path = Path(path)
    file_size = file_path.stat().st_size
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if length <= 0:
        raise ValueError("length must be > 0")
    if width <= 0:
        raise ValueError("width must be > 0")

    with file_path.open("rb") as file:
        file.seek(offset)
        data = file.read(length)

    rows = []
    for row_offset in range(0, len(data), width):
        chunk = data[row_offset : row_offset + width]
        absolute = offset + row_offset
        rows.append(
            {
                "offset": f"0x{absolute:X}",
                "hex": " ".join(f"{byte:02X}" for byte in chunk),
                "ascii": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk),
            }
        )

    return {
        "path": str(file_path),
        "file_size": file_size,
        "offset": f"0x{offset:X}",
        "length_requested": length,
        "length_read": len(data),
        "entropy": calculate_entropy(data),
        "rows": rows,
    }


def parse_integer(value: str | int | None, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value)


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
