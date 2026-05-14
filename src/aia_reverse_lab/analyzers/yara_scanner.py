from __future__ import annotations

from pathlib import Path
from typing import Any


class YaraUnavailableError(RuntimeError):
    """Raised when yara-python is not installed."""


def scan_with_yara(target: str | Path, rules_path: str | Path | None) -> list[dict[str, Any]]:
    """Scan target with YARA rules when a rules path is provided.

    The scanner is passive: it reads the target file and applies user-provided YARA rules.
    """
    if rules_path is None:
        return []

    try:
        import yara  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise YaraUnavailableError(
            "yara-python is not installed. Install with: pip install -e .[yara]"
        ) from exc

    target_path = Path(target)
    rule_sources = collect_rule_sources(Path(rules_path))
    if not rule_sources:
        return []

    compiled_rules = yara.compile(filepaths=rule_sources)
    matches = compiled_rules.match(str(target_path))
    return [format_match(match) for match in matches]


def collect_rule_sources(path: Path) -> dict[str, str]:
    if path.is_file():
        return {path.stem: str(path)}

    if not path.is_dir():
        raise FileNotFoundError(f"YARA rules path does not exist: {path}")

    rule_sources: dict[str, str] = {}
    for rule_path in sorted(path.rglob("*")):
        if rule_path.is_file() and rule_path.suffix.lower() in {".yar", ".yara"}:
            namespace = unique_namespace(rule_sources, rule_path.stem)
            rule_sources[namespace] = str(rule_path)
    return rule_sources


def unique_namespace(existing: dict[str, str], base: str) -> str:
    namespace = base or "rules"
    if namespace not in existing:
        return namespace

    index = 2
    while f"{namespace}_{index}" in existing:
        index += 1
    return f"{namespace}_{index}"


def format_match(match) -> dict[str, Any]:
    strings: list[dict[str, Any]] = []
    for string_match in getattr(match, "strings", []):
        for instance in getattr(string_match, "instances", []):
            strings.append(
                {
                    "identifier": getattr(string_match, "identifier", ""),
                    "offset": f"0x{getattr(instance, 'offset', 0):X}",
                    "matched_length": getattr(instance, "matched_length", 0),
                }
            )

    return {
        "rule": getattr(match, "rule", ""),
        "namespace": getattr(match, "namespace", ""),
        "tags": list(getattr(match, "tags", [])),
        "meta": dict(getattr(match, "meta", {})),
        "strings": strings[:200],
        "string_match_count": len(strings),
    }
