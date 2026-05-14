from __future__ import annotations

import base64
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote


@dataclass(slots=True)
class Rule:
    name: str
    pattern: str
    flags: int = 0

    def matches(self, value: str) -> bool:
        return re.search(self.pattern, value, self.flags) is not None


def load_rules(path: str | Path) -> list[Rule]:
    rules_path = Path(path)
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    rules: list[Rule] = []
    if isinstance(data, dict):
        items = data.get("rules", [])
    else:
        items = data
    for item in items:
        flags = 0
        for flag in item.get("flags", []):
            if str(flag).lower() == "ignorecase":
                flags |= re.IGNORECASE
            if str(flag).lower() == "multiline":
                flags |= re.MULTILINE
        rules.append(Rule(name=str(item["name"]), pattern=str(item["pattern"]), flags=flags))
    return rules


def run_bypass_resilience_lab(
    *,
    sample: str | None = None,
    sample_file: str | Path | None = None,
    rules_file: str | Path,
    max_variants: int = 200,
) -> dict[str, Any]:
    if sample_file:
        base_value = Path(sample_file).read_text(encoding="utf-8", errors="replace")
    elif sample is not None:
        base_value = sample
    else:
        raise ValueError("sample or sample_file is required")

    rules = load_rules(rules_file)
    variants = generate_variants(base_value)[:max_variants]
    results = []
    for variant in variants:
        hits = [rule.name for rule in rules if rule.matches(variant["value"])]
        results.append(
            {
                "variant_id": variant["id"],
                "kind": variant["kind"],
                "value_preview": variant["value"][:200],
                "hit_count": len(hits),
                "hits": hits,
                "missed": len(hits) == 0,
            }
        )

    missed = [item for item in results if item["missed"]]
    hit = [item for item in results if not item["missed"]]
    return {
        "sample_length": len(base_value),
        "rule_count": len(rules),
        "variant_count": len(results),
        "hit_variant_count": len(hit),
        "miss_variant_count": len(missed),
        "miss_rate": round(len(missed) / len(results), 4) if results else 0.0,
        "results": results,
        "remediation_hints": build_remediation_hints(missed),
        "note": "Local defensive rule resilience test only. This is not a protection bypass or third-party evasion tool.",
    }


def generate_variants(value: str) -> list[dict[str, str]]:
    candidates: list[tuple[str, str]] = []
    candidates.append(("original", value))
    candidates.append(("lowercase", value.lower()))
    candidates.append(("uppercase", value.upper()))
    candidates.append(("casefold", value.casefold()))
    candidates.append(("trim", value.strip()))
    candidates.append(("collapse_spaces", re.sub(r"\s+", " ", value)))
    candidates.append(("remove_spaces", re.sub(r"\s+", "", value)))
    candidates.append(("tab_separated", "\t".join(value.split())))
    candidates.append(("newline_separated", "\n".join(value.split())))
    candidates.append(("nfc", unicodedata.normalize("NFC", value)))
    candidates.append(("nfd", unicodedata.normalize("NFD", value)))
    candidates.append(("nfkc", unicodedata.normalize("NFKC", value)))
    candidates.append(("nfkd", unicodedata.normalize("NFKD", value)))
    candidates.append(("url_encoded", quote(value, safe="")))
    candidates.append(("url_encoded_spaces_safe", quote(value, safe="/")))
    candidates.append(("hex_utf8", value.encode("utf-8", errors="replace").hex()))
    candidates.append(("base64_utf8", base64.b64encode(value.encode("utf-8", errors="replace")).decode("ascii")))
    candidates.append(("prefix_space", " " + value))
    candidates.append(("suffix_space", value + " "))
    candidates.append(("wrapped_quotes", f'"{value}"'))
    candidates.append(("wrapped_single_quotes", f"'{value}'"))
    candidates.append(("null_suffix_visible", value + "\\x00"))
    candidates.append(("crlf_suffix", value + "\r\n"))

    words = value.split()
    if len(words) > 1:
        candidates.append(("double_space_between_words", "  ".join(words)))
        candidates.append(("slash_between_words", "/".join(words)))
        candidates.append(("dot_between_words", ".".join(words)))
        candidates.append(("underscore_between_words", "_".join(words)))
        candidates.append(("dash_between_words", "-".join(words)))

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for kind, candidate in candidates:
        key = f"{kind}\0{candidate}"
        if key in seen:
            continue
        seen.add(key)
        unique.append({"id": str(len(unique)), "kind": kind, "value": candidate})
    return unique


def build_remediation_hints(missed: list[dict[str, Any]]) -> list[str]:
    if not missed:
        return ["No miss variants found. Keep canonicalization and tests in CI."]
    kinds = {str(item.get("kind", "")) for item in missed}
    hints: list[str] = []
    if any("case" in kind or kind in {"lowercase", "uppercase"} for kind in kinds):
        hints.append("Normalize case before rule matching or use explicit ignorecase rules.")
    if any("space" in kind or "separated" in kind or "trim" in kind for kind in kinds):
        hints.append("Canonicalize whitespace before validation and define strict whitespace grammar.")
    if any(kind.startswith("nf") for kind in kinds):
        hints.append("Normalize Unicode with NFC/NFKC before validation.")
    if any("url_encoded" in kind for kind in kinds):
        hints.append("Decode percent-encoding exactly once before validation, then reject ambiguous double-encoding.")
    if any("hex" in kind or "base64" in kind for kind in kinds):
        hints.append("Classify and decode allowed encodings before validation, or reject encoded forms at boundaries.")
    if any("null" in kind or "crlf" in kind for kind in kinds):
        hints.append("Reject unexpected control characters and normalize line endings at input boundaries.")
    return hints or ["Review missed variants and add explicit parser/canonicalization tests."]
