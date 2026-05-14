from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from aia_reverse_lab.tools.result_triage import triage_result_file

FAIL_STATUSES = {"crash", "hang", "timeout", "parse-error", "unknown"}
HIGH_SEVERITIES = {"critical", "high"}


def compare_triage_results(
    before_path: str | Path,
    after_path: str | Path,
    *,
    allow_new_unknown: bool = False,
) -> dict[str, Any]:
    before = triage_result_file(before_path)
    after = triage_result_file(after_path)

    before_records = normalize_records_by_case(before.get("records", []))
    after_records = normalize_records_by_case(after.get("records", []))

    before_counts = Counter(record["status"] for record in before_records.values())
    after_counts = Counter(record["status"] for record in after_records.values())
    before_severity = Counter(record["severity"] for record in before_records.values())
    after_severity = Counter(record["severity"] for record in after_records.values())

    before_failures = {case_id: record for case_id, record in before_records.items() if is_failure(record)}
    after_failures = {case_id: record for case_id, record in after_records.items() if is_failure(record)}

    new_failures = [after_failures[key] for key in sorted(after_failures) if key not in before_failures]
    resolved_failures = [before_failures[key] for key in sorted(before_failures) if key not in after_failures]
    persistent_failures = [after_failures[key] for key in sorted(after_failures) if key in before_failures]

    before_fail_rate = fail_rate(before_records)
    after_fail_rate = fail_rate(after_records)
    deltas = {
        "record_count": len(after_records) - len(before_records),
        "failure_count": len(after_failures) - len(before_failures),
        "fail_rate": round(after_fail_rate - before_fail_rate, 4),
        "crash_count": after_counts.get("crash", 0) - before_counts.get("crash", 0),
        "timeout_hang_count": (after_counts.get("timeout", 0) + after_counts.get("hang", 0)) - (before_counts.get("timeout", 0) + before_counts.get("hang", 0)),
        "parse_error_count": after_counts.get("parse-error", 0) - before_counts.get("parse-error", 0),
        "critical_high_count": sum(after_severity.get(item, 0) for item in HIGH_SEVERITIES) - sum(before_severity.get(item, 0) for item in HIGH_SEVERITIES),
    }

    gate_failures = build_gate_failures(deltas, new_failures, allow_new_unknown=allow_new_unknown)
    passed = not gate_failures

    return {
        "passed": passed,
        "decision": "pass" if passed else "fail",
        "before_source": str(before_path),
        "after_source": str(after_path),
        "before": {
            "record_count": len(before_records),
            "status_counts": dict(before_counts),
            "severity_counts": dict(before_severity),
            "failure_count": len(before_failures),
            "fail_rate": before_fail_rate,
        },
        "after": {
            "record_count": len(after_records),
            "status_counts": dict(after_counts),
            "severity_counts": dict(after_severity),
            "failure_count": len(after_failures),
            "fail_rate": after_fail_rate,
        },
        "deltas": deltas,
        "new_failure_count": len(new_failures),
        "resolved_failure_count": len(resolved_failures),
        "persistent_failure_count": len(persistent_failures),
        "new_failures": compact_cases(new_failures),
        "resolved_failures": compact_cases(resolved_failures),
        "persistent_failures": compact_cases(persistent_failures[:100]),
        "gate_failures": gate_failures,
        "remediation_hints": build_remediation_hints(deltas, new_failures, persistent_failures),
        "note": "Defensive regression gate only. This compares test outcomes and does not execute targets.",
    }


def normalize_records_by_case(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        case_id = str(record.get("case_id", index))
        normalized[case_id] = record
    return normalized


def is_failure(record: dict[str, Any]) -> bool:
    return str(record.get("status", "unknown")) in FAIL_STATUSES


def fail_rate(records: dict[str, dict[str, Any]]) -> float:
    if not records:
        return 0.0
    failures = sum(1 for record in records.values() if is_failure(record))
    return round(failures / len(records), 4)


def build_gate_failures(
    deltas: dict[str, Any],
    new_failures: list[dict[str, Any]],
    *,
    allow_new_unknown: bool,
) -> list[str]:
    failures: list[str] = []
    if deltas["crash_count"] > 0:
        failures.append(f"Crash count increased by {deltas['crash_count']}.")
    if deltas["timeout_hang_count"] > 0:
        failures.append(f"Timeout/hang count increased by {deltas['timeout_hang_count']}.")
    if deltas["failure_count"] > 0:
        failures.append(f"Failure count increased by {deltas['failure_count']}.")
    if deltas["fail_rate"] > 0:
        failures.append(f"Fail rate increased by {deltas['fail_rate']}.")
    if deltas["critical_high_count"] > 0:
        failures.append(f"Critical/high severity count increased by {deltas['critical_high_count']}.")
    if new_failures:
        if allow_new_unknown and all(item.get("status") == "unknown" for item in new_failures):
            return failures
        failures.append(f"New failing cases detected: {len(new_failures)}.")
    return failures


def compact_cases(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for record in records:
        compact.append(
            {
                "case_id": record.get("case_id"),
                "case_path": record.get("case_path"),
                "mutation": record.get("mutation"),
                "status": record.get("status"),
                "severity": record.get("severity"),
                "exit_code": record.get("exit_code"),
                "duration_ms": record.get("duration_ms"),
                "tags": record.get("tags", []),
            }
        )
    return compact


def build_remediation_hints(
    deltas: dict[str, Any],
    new_failures: list[dict[str, Any]],
    persistent_failures: list[dict[str, Any]],
) -> list[str]:
    hints: list[str] = []
    if deltas["crash_count"] > 0:
        hints.append("Crash regression detected. Block release until new crash cases are minimized and converted into regression tests.")
    if deltas["timeout_hang_count"] > 0:
        hints.append("Timeout/hang regression detected. Add parser iteration caps, payload size limits, and timeout handling.")
    if new_failures:
        mutations = sorted({str(item.get("mutation", "unknown")) for item in new_failures})
        hints.append(f"New failing mutation types: {', '.join(mutations)}. Review these input classes first.")
    if persistent_failures:
        hints.append("Persistent failures remain. Prioritize critical/high cases and keep their corpus files as mandatory CI fixtures.")
    if not hints:
        hints.append("No regression detected. Keep before/after summaries as release evidence.")
    return hints
