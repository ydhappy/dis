from __future__ import annotations

import json

from aia_reverse_lab.tools.bypass_resilience import run_bypass_resilience_lab
from aia_reverse_lab.tools.crypto_transform import transform_bytes
from aia_reverse_lab.tools.dump_viewer import view_binary_range
from aia_reverse_lab.tools.regression_guard import compare_triage_results
from aia_reverse_lab.tools.result_triage import triage_result_file
from aia_reverse_lab.tools.robustness_tester import generate_robustness_corpus


def test_crypto_transform_roundtrip() -> None:
    encoded = transform_bytes(operation="base64-encode", data=b"hello")
    assert encoded == b"aGVsbG8="
    decoded = transform_bytes(operation="base64-decode", data=encoded)
    assert decoded == b"hello"

    hexed = transform_bytes(operation="hex-encode", data=b"AIA")
    assert hexed == b"414941"
    assert transform_bytes(operation="hex-decode", data=hexed) == b"AIA"

    assert transform_bytes(operation="xor", data=b"\x00\x01", key="hex:01") == b"\x01\x00"


def test_dump_viewer_reads_range(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ABCDEF\x00\xff")

    result = view_binary_range(sample, offset=0, length=8, width=4)

    assert result["length_read"] == 8
    assert result["rows"][0]["hex"] == "41 42 43 44"
    assert result["rows"][0]["ascii"] == "ABCD"
    assert result["rows"][1]["ascii"] == "EF.."


def test_robustness_corpus_generation(tmp_path) -> None:
    sample = tmp_path / "packet.bin"
    output = tmp_path / "corpus"
    sample.write_bytes(b"HEADER:value=1234")

    result = generate_robustness_corpus(sample, output, seed=7, max_cases=8)

    assert result["case_count"] == 8
    assert (output / "robustness_summary.json").exists()
    assert all((tmp_path / item["path"]).exists() if not item["path"].startswith(str(tmp_path)) else True for item in result["cases"])


def test_bypass_resilience_finds_misses(tmp_path) -> None:
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {"name": "admin_rule", "pattern": "admin", "flags": ["ignorecase"]},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_bypass_resilience_lab(sample="admin token", rules_file=rules, max_variants=50)

    assert result["rule_count"] == 1
    assert result["variant_count"] > 1
    assert result["hit_variant_count"] >= 1
    assert result["miss_variant_count"] >= 1
    assert result["remediation_hints"]


def test_result_triage_jsonl(tmp_path) -> None:
    results = tmp_path / "results.jsonl"
    results.write_text(
        "\n".join(
            [
                json.dumps({"case_id": 1, "case_path": "corpus/case_0001_edge_byte.bin", "status": "crash", "exit_code": 139, "duration_ms": 10, "stderr": "segmentation fault"}),
                json.dumps({"case_id": 2, "case_path": "corpus/case_0002_truncate.bin", "status": "ok", "exit_code": 0, "duration_ms": 3}),
            ]
        ),
        encoding="utf-8",
    )

    result = triage_result_file(results)

    assert result["record_count"] == 2
    assert result["status_counts"]["crash"] == 1
    assert result["severity_counts"]["critical"] == 1
    assert result["top_failures"][0]["case_id"] == 1


def test_regression_guard_passes_when_failures_decrease(tmp_path) -> None:
    before = tmp_path / "before.jsonl"
    after = tmp_path / "after.jsonl"
    before.write_text(
        "\n".join(
            [
                json.dumps({"case_id": 1, "case_path": "corpus/case_0001_edge_byte.bin", "status": "crash", "exit_code": 139}),
                json.dumps({"case_id": 2, "case_path": "corpus/case_0002_truncate.bin", "status": "timeout"}),
            ]
        ),
        encoding="utf-8",
    )
    after.write_text(
        "\n".join(
            [
                json.dumps({"case_id": 1, "case_path": "corpus/case_0001_edge_byte.bin", "status": "ok", "exit_code": 0}),
                json.dumps({"case_id": 2, "case_path": "corpus/case_0002_truncate.bin", "status": "ok", "exit_code": 0}),
            ]
        ),
        encoding="utf-8",
    )

    result = compare_triage_results(before, after)

    assert result["passed"] is True
    assert result["deltas"]["failure_count"] == -2
    assert result["resolved_failure_count"] == 2


def test_regression_guard_fails_on_new_crash(tmp_path) -> None:
    before = tmp_path / "before.jsonl"
    after = tmp_path / "after.jsonl"
    before.write_text(json.dumps({"case_id": 1, "status": "ok", "exit_code": 0}), encoding="utf-8")
    after.write_text(json.dumps({"case_id": 1, "status": "crash", "exit_code": 139, "stderr": "access violation"}), encoding="utf-8")

    result = compare_triage_results(before, after)

    assert result["passed"] is False
    assert result["decision"] == "fail"
    assert result["gate_failures"]
