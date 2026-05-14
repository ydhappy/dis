from __future__ import annotations

import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any

EDGE_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 0x20, 0x0A, 0x0D]


def analyze_input_profile(data: bytes) -> dict[str, Any]:
    length = len(data)
    if length == 0:
        return {
            "length": 0,
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": 0.0,
            "null_ratio": 0.0,
            "ascii_ratio": 0.0,
            "control_ratio": 0.0,
            "unique_byte_count": 0,
        }
    null_count = data.count(0)
    ascii_count = sum(1 for byte in data if 32 <= byte <= 126)
    control_count = sum(1 for byte in data if byte < 32 or byte == 127)
    return {
        "length": length,
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": calculate_entropy(data),
        "null_ratio": round(null_count / length, 4),
        "ascii_ratio": round(ascii_count / length, 4),
        "control_ratio": round(control_count / length, 4),
        "unique_byte_count": len(set(data)),
    }


def generate_robustness_corpus(
    input_file: str | Path,
    output_dir: str | Path,
    *,
    seed: int = 1337,
    max_cases: int = 64,
) -> dict[str, Any]:
    source_path = Path(input_file)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = source_path.read_bytes()
    rng = random.Random(seed)
    source_profile = analyze_input_profile(data)

    cases: list[dict[str, Any]] = []
    if not data:
        summary = {
            "source": str(source_path),
            "output_dir": str(out),
            "seed": seed,
            "source_profile": source_profile,
            "case_count": 0,
            "cases": [],
            "note": "Empty input; no mutation cases generated.",
        }
        write_summary(out, summary)
        return summary

    planned = []
    positions = interesting_positions(len(data), rng, max_cases=max(8, max_cases // 2))
    for position in positions:
        planned.append(("flip_bit", position, None))
        planned.append(("edge_byte", position, rng.choice(EDGE_BYTES)))
    planned.extend(("truncate", max(1, len(data) // divisor), None) for divisor in [2, 3, 4, 8])
    planned.extend(("append_edge", -1, byte) for byte in EDGE_BYTES)
    planned.extend(("zero_range", position, None) for position in positions[:8])
    planned = planned[:max_cases]

    for index, (mutation, position, value) in enumerate(planned):
        mutated = mutate(data, mutation, position, value)
        name = f"case_{index:04d}_{mutation}.bin"
        case_path = out / name
        case_path.write_bytes(mutated)
        cases.append(
            {
                "id": index,
                "mutation": mutation,
                "position": position if position >= 0 else None,
                "value": f"0x{value:02X}" if isinstance(value, int) else None,
                "path": str(case_path),
                "profile": analyze_input_profile(mutated),
                "delta": profile_delta(source_profile, analyze_input_profile(mutated)),
            }
        )

    summary = {
        "source": str(source_path),
        "output_dir": str(out),
        "seed": seed,
        "source_profile": source_profile,
        "case_count": len(cases),
        "cases": cases,
        "note": "Defensive local corpus generation only. Run cases only against systems you own or are authorized to test.",
    }
    write_summary(out, summary)
    return summary


def interesting_positions(length: int, rng: random.Random, max_cases: int) -> list[int]:
    base = {0, 1, 2, 3, max(0, length - 1), max(0, length - 2), length // 2, length // 4, (length * 3) // 4}
    while len(base) < max_cases and length > 0:
        base.add(rng.randrange(0, length))
    return sorted(position for position in base if 0 <= position < length)[:max_cases]


def mutate(data: bytes, mutation: str, position: int, value: int | None) -> bytes:
    blob = bytearray(data)
    if mutation == "flip_bit":
        blob[position] ^= 0x01
        return bytes(blob)
    if mutation == "edge_byte":
        blob[position] = int(value or 0)
        return bytes(blob)
    if mutation == "truncate":
        return bytes(blob[:position])
    if mutation == "append_edge":
        blob.append(int(value or 0))
        return bytes(blob)
    if mutation == "zero_range":
        end = min(len(blob), position + 16)
        for index in range(position, end):
            blob[index] = 0
        return bytes(blob)
    raise ValueError(f"Unsupported mutation: {mutation}")


def profile_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    keys = ["length", "entropy", "null_ratio", "ascii_ratio", "control_ratio", "unique_byte_count"]
    return {key: round(float(after[key]) - float(before[key]), 4) for key in keys}


def write_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    (output_dir / "robustness_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


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
