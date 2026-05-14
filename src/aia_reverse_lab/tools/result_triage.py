from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any

KNOWN_STATUSES = {"ok", "crash", "hang", "timeout", "parse-error", "reject", "unknown"}
ERROR_KEYWORDS = {
    "segfault": re.compile(r"segmentation fault|sigsegv|access violation", re.I),
    "assertion": re.compile(r"assert|assertion", re.I),
    "overflow": re.compile(r"overflow|out of bounds|bounds", re.I),
    "decode_error": re.compile(r"decode|codec|utf|unicode|invalid byte", re.I),
    "timeout": re.compile(r"timeout|timed out|hang", re.I),
    "exception": re.compile(r"exception|traceback|stack trace", re.I),
}


def triage_result_file(path: str | Path) -> dict[str, Any]:
    records = load_records(path)
    normalized = [normalize_record(item, index) for index, item in enumerate(records)]
    status_counts = Counter(item["status"] for item in normalized)
    severity_counts = Counter(item["severity"] for item in normalized)
    keyword_counts = Counter(keyword for item in normalized for keyword in item["tags"])
    mutation_stats = build_mutation_stats(normalized)
    duration_stats = build_duration_stats(normalized)
    top_failures = sorted(
        [item for item in normalized if item["status"] not in {"ok", "reject"}],
        key=lambda item: (severity_rank(item["severity"]), item.get("duration_ms") or 0),
        reverse=True,
    )[:50]

    return {
        "source": str(path),
        "record_count": len(normalized),
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "keyword_counts": dict(keyword_counts),
        "mutation_stats": mutation_stats,
        "duration_stats": duration_stats,
        "top_failures": top_failures,
        "remediation_hints": build_remediation_hints(status_counts, keyword_counts, mutation_stats),
        "records": normalized,
        "note": "Defensive result triage only. This tool does not execute targets or prove exploitability.",
    }


def load_records(path: str | Path) -> list[dict[str, Any]]:
    result_path = Path(path)
    text = result_path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("JSON result file must contain a list of records.")
        return [dict(item) for item in data]
    if stripped.startswith("{"):
        data = json.loads(stripped)
        if isinstance(data.get("records"), list):
            return [dict(item) for item in data["records"]]
        if isinstance(data.get("results"), list):
            return [dict(item) for item in data["results"]]
        return [dict(data)]
    records = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(dict(json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at line {line_no}: {exc}") from exc
    return records


def normalize_record(record: dict[str, Any], fallback_id: int) -> dict[str, Any]:
    status = normalize_status(str(record.get("status", "unknown")), record)
    stderr = str(record.get("stderr", "") or "")
    stdout = str(record.get("stdout", "") or "")
    message = "\n".join([stderr, stdout])
    tags = detect_tags(message)
    case_path = str(record.get("case_path") or record.get("path") or "")
    mutation = str(record.get("mutation") or infer_mutation(case_path) or "unknown")
    duration_ms = normalize_number(record.get("duration_ms"))
    exit_code = normalize_number(record.get("exit_code"))
    severity = classify_severity(status, tags, exit_code, duration_ms)
    return {
        "case_id": record.get("case_id", record.get("id", fallback_id)),
        "case_path": case_path,
        "mutation": mutation,
        "status": status,
        "severity": severity,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "tags": tags,
        "stderr_preview": stderr[:500],
        "stdout_preview": stdout[:500],
    }


def normalize_status(status: str, record: dict[str, Any]) -> str:
    status = status.lower().strip().replace("_", "-")
    if status in KNOWN_STATUSES:
        return status
    exit_code = normalize_number(record.get("exit_code"))
    stderr = str(record.get("stderr", "") or "")
    if exit_code is not None and exit_code != 0:
        if re.search(r"segmentation fault|sigsegv|access violation|core dumped", stderr, re.I):
            return "crash"
        return "parse-error"
    if re.search(r"timeout|timed out", stderr, re.I):
        return "timeout"
    return "unknown"


def normalize_number(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def detect_tags(message: str) -> list[str]:
    tags = []
    for name, pattern in ERROR_KEYWORDS.items():
        if pattern.search(message):
            tags.append(name)
    return tags


def infer_mutation(path: str) -> str | None:
    match = re.search(r"case_\d+_([a-zA-Z0-9_-]+)\.bin", path)
    if match:
        return match.group(1)
    return None


def classify_severity(status: str, tags: list[str], exit_code: int | None, duration_ms: int | None) -> str:
    if status == "crash" or "segfault" in tags:
        return "critical"
    if status in {"hang", "timeout"} or "timeout" in tags:
        return "high"
    if status == "parse-error" or exit_code not in {None, 0}:
        return "medium"
    if status == "unknown":
        return "low"
    return "info"


def build_mutation_stats(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("mutation", "unknown"))].append(record)
    stats = []
    for mutation, items in grouped.items():
        fail_count = sum(1 for item in items if item["status"] not in {"ok", "reject"})
        crash_count = sum(1 for item in items if item["status"] == "crash")
        timeout_count = sum(1 for item in items if item["status"] in {"hang", "timeout"})
        stats.append(
            {
                "mutation": mutation,
                "count": len(items),
                "fail_count": fail_count,
                "crash_count": crash_count,
                "timeout_count": timeout_count,
                "fail_rate": round(fail_count / len(items), 4) if items else 0.0,
            }
        )
    return sorted(stats, key=lambda item: (item["fail_rate"], item["crash_count"], item["timeout_count"]), reverse=True)


def build_duration_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    values = [int(item["duration_ms"]) for item in records if item.get("duration_ms") is not None]
    if not values:
        return {"available": False}
    return {
        "available": True,
        "count": len(values),
        "min_ms": min(values),
        "max_ms": max(values),
        "mean_ms": round(mean(values), 2),
        "median_ms": round(median(values), 2),
    }


def severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def build_remediation_hints(status_counts: Counter, keyword_counts: Counter, mutation_stats: list[dict[str, Any]]) -> list[str]:
    hints = []
    if status_counts.get("crash", 0):
        hints.append("Crash cases exist. Add bounds checks, length validation, and structured error handling around parser/decoder boundaries.")
    if status_counts.get("timeout", 0) or status_counts.get("hang", 0):
        hints.append("Timeout/hang cases exist. Add parser iteration limits, payload size caps, and watchdog timeouts.")
    if keyword_counts.get("decode_error", 0):
        hints.append("Decode errors detected. Normalize encodings at input boundaries and reject malformed byte sequences safely.")
    if keyword_counts.get("overflow", 0):
        hints.append("Overflow/bounds indicators detected. Review integer conversion, allocation size, and index arithmetic.")
    for item in mutation_stats[:3]:
        if item.get("fail_rate", 0) > 0:
            hints.append(f"Mutation type '{item['mutation']}' has fail_rate={item['fail_rate']}. Add targeted regression tests for this mutation.")
    return hints or ["No major failure pattern detected. Keep these cases as regression tests."]
