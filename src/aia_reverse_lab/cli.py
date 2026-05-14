from __future__ import annotations

import argparse
import json
from pathlib import Path

import pefile
from rich.console import Console
from rich.table import Table

from aia_reverse_lab import __version__
from aia_reverse_lab.analyzers.patch_diff import analyze_binary_diff
from aia_reverse_lab.analyzers.pe_analyzer import PEAnalyzer
from aia_reverse_lab.reporting.report_generator import write_reports
from aia_reverse_lab.storage.database import AnalysisDatabase
from aia_reverse_lab.tools.crypto_transform import (
    TransformError,
    read_input_bytes,
    transform_bytes,
    write_output_bytes,
)
from aia_reverse_lab.tools.dump_viewer import parse_integer as parse_dump_integer
from aia_reverse_lab.tools.dump_viewer import view_binary_range
from aia_reverse_lab.tools.memory_dump_analyzer import analyze_memory_dump
from aia_reverse_lab.tools.opcode_viewer import (
    OpcodeViewerError,
    disassemble_file_range,
    disassemble_hex_string,
    parse_integer as parse_opcode_integer,
)
from aia_reverse_lab.tools.pcap_analyzer import analyze_pcap

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aia-reverse-lab", description="Defensive EXE/DLL binary analysis workbench")
    parser.add_argument("target", nargs="?", help="Path to EXE/DLL file to analyze")
    parser.add_argument("--out", default="reports", help="Output directory for analysis reports. Default: reports")
    parser.add_argument("--db", default="aia_reverse_lab.sqlite3", help="SQLite database path. Default: aia_reverse_lab.sqlite3")
    parser.add_argument("--yara-rules", default=None, help="Optional YARA rule file or directory to scan with.")
    parser.add_argument("--disasm", action="store_true", help="Enable passive static EntryPoint disassembly using optional Capstone.")
    parser.add_argument("--disasm-limit", type=int, default=80, help="Maximum number of EntryPoint instructions to disassemble. Default: 80")
    parser.add_argument("--diff-original", default=None, help="Original authorized file for safe binary diff mode.")
    parser.add_argument("--diff-modified", default=None, help="Modified authorized file for safe binary diff mode.")
    parser.add_argument("--diff-max-ranges", type=int, default=200, help="Maximum changed ranges to report. Default: 200")
    parser.add_argument("--dump-view", default=None, help="View a file byte range as hex/ascii.")
    parser.add_argument("--dump-offset", default="0", help="Offset for --dump-view. Decimal or 0x hex. Default: 0")
    parser.add_argument("--dump-length", default="256", help="Length for --dump-view. Decimal or 0x hex. Default: 256")
    parser.add_argument("--dump-width", type=int, default=16, help="Hexdump row width. Default: 16")
    parser.add_argument("--memdump", default=None, help="Analyze an existing offline memory dump file.")
    parser.add_argument("--memdump-max-strings", type=int, default=200, help="Max strings for --memdump. Default: 200")
    parser.add_argument("--memdump-max-regions", type=int, default=200, help="Max entropy regions for --memdump. Default: 200")
    parser.add_argument("--pcap", default=None, help="Analyze an existing offline PCAP file.")
    parser.add_argument("--pcap-max-packets", type=int, default=100, help="Max packets for --pcap. Default: 100")
    parser.add_argument("--pcap-payload-preview", type=int, default=64, help="Payload preview bytes for --pcap. Default: 64")
    parser.add_argument("--opcode-file", default=None, help="Disassemble a selected file byte range.")
    parser.add_argument("--opcode-hex", default=None, help="Disassemble a raw hex byte string.")
    parser.add_argument("--opcode-offset", default="0", help="Offset for --opcode-file. Decimal or 0x hex. Default: 0")
    parser.add_argument("--opcode-length", default="256", help="Length for --opcode-file. Decimal or 0x hex. Default: 256")
    parser.add_argument("--opcode-base", default=None, help="Base address for opcode viewer. Decimal or 0x hex.")
    parser.add_argument("--opcode-arch", default="x64", help="Opcode architecture: x86, x64, arm, arm64. Default: x64")
    parser.add_argument("--opcode-limit", type=int, default=200, help="Max decoded instructions. Default: 200")
    parser.add_argument("--tool-json", default=None, help="Optional path to save viewer/tool JSON output.")
    parser.add_argument("--transform", default=None, help="Safe transform operation: base64-decode, base64-encode, hex-decode, hex-encode, url-decode, xor")
    parser.add_argument("--transform-input", default=None, help="Input text for safe transform mode.")
    parser.add_argument("--transform-input-file", default=None, help="Input file for safe transform mode.")
    parser.add_argument("--transform-output-file", default=None, help="Optional output file for safe transform mode.")
    parser.add_argument("--transform-key", default=None, help="User-supplied key for xor transform. Prefix with hex: or utf8: if needed.")
    parser.add_argument("--recent", action="store_true", help="Show recent analyses from the SQLite database and exit.")
    parser.add_argument("--recent-limit", type=int, default=20, help="Number of recent analyses to show with --recent. Default: 20")
    parser.add_argument("--version", action="version", version=f"aia-reverse-lab {__version__}")
    return parser


def save_tool_json(payload: dict, path: str | None) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"JSON Output : {output}")


def run_dump_view_mode(args) -> int:
    try:
        result = view_binary_range(args.dump_view, offset=parse_dump_integer(args.dump_offset), length=parse_dump_integer(args.dump_length, 256), width=args.dump_width)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Dump view failed:[/red] {exc}")
        return 2
    table = Table(title="Binary Dump View")
    table.add_column("Offset", style="cyan")
    table.add_column("Hex", style="white")
    table.add_column("ASCII", style="green")
    for row in result["rows"]:
        table.add_row(row["offset"], row["hex"], row["ascii"])
    console.print(table)
    console.print(f"Entropy: {result['entropy']} | Read: {result['length_read']} bytes")
    save_tool_json(result, args.tool_json)
    return 0


def run_memory_dump_mode(args) -> int:
    try:
        result = analyze_memory_dump(args.memdump, max_strings=max(args.memdump_max_strings, 1), max_regions=max(args.memdump_max_regions, 1))
    except (OSError, ValueError) as exc:
        console.print(f"[red]Memory dump analysis failed:[/red] {exc}")
        return 2
    summary = Table(title="Offline Memory Dump Analysis")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="white")
    for key in ["path", "size", "mz_signature_count", "pe_signature_count", "string_count", "high_entropy_region_count"]:
        summary.add_row(key, str(result.get(key, "")))
    console.print(summary)
    if result.get("strings"):
        strings = Table(title="Dump Strings")
        strings.add_column("Offset", style="cyan")
        strings.add_column("Length", style="white")
        strings.add_column("Value", style="white")
        for item in result["strings"][:30]:
            strings.add_row(str(item["offset"]), str(item["length"]), str(item["value"]))
        console.print(strings)
    save_tool_json(result, args.tool_json)
    return 0


def run_pcap_mode(args) -> int:
    try:
        result = analyze_pcap(args.pcap, max_packets=max(args.pcap_max_packets, 1), payload_preview=max(args.pcap_payload_preview, 0))
    except (OSError, ValueError) as exc:
        console.print(f"[red]PCAP analysis failed:[/red] {exc}")
        return 2
    summary = Table(title="Offline PCAP Analysis")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="white")
    for key in ["path", "size", "version", "snaplen", "network", "packet_count_returned"]:
        summary.add_row(key, str(result.get(key, "")))
    console.print(summary)
    packets = Table(title="Packets")
    packets.add_column("Time", style="cyan")
    packets.add_column("Layers", style="white")
    packets.add_column("Payload Preview", style="green")
    for packet in result.get("packets", [])[:50]:
        layers = " / ".join(layer.get("name", "?") for layer in packet.get("layers", []))
        packets.add_row(str(packet.get("timestamp", "")), layers, str(packet.get("payload_preview_ascii", packet.get("payload_preview_hex", ""))))
    console.print(packets)
    save_tool_json(result, args.tool_json)
    return 0


def run_opcode_mode(args) -> int:
    try:
        base = parse_opcode_integer(args.opcode_base, 0) if args.opcode_base is not None else None
        if args.opcode_hex:
            result = disassemble_hex_string(hex_string=args.opcode_hex, architecture=args.opcode_arch, base_address=base or 0, instruction_limit=max(args.opcode_limit, 1))
        else:
            result = disassemble_file_range(path=args.opcode_file, offset=parse_opcode_integer(args.opcode_offset), length=parse_opcode_integer(args.opcode_length, 256), architecture=args.opcode_arch, base_address=base, instruction_limit=max(args.opcode_limit, 1))
    except (OSError, ValueError, OpcodeViewerError) as exc:
        console.print(f"[red]Opcode viewer failed:[/red] {exc}")
        return 2
    table = Table(title="Opcode Viewer")
    table.add_column("Address", style="cyan")
    table.add_column("Bytes", style="white")
    table.add_column("Instruction", style="green")
    for item in result.get("instructions", []):
        table.add_row(item["address"], item["bytes"], f"{item['mnemonic']} {item['op_str']}".strip())
    console.print(table)
    console.print(f"Instructions: {result.get('instruction_count', 0)} | Bytes: {result.get('byte_count', 0)}")
    save_tool_json(result, args.tool_json)
    return 0


def run_transform_mode(args) -> int:
    try:
        data = read_input_bytes(args.transform_input, args.transform_input_file)
        transformed = transform_bytes(operation=args.transform, data=data, key=args.transform_key)
        output = write_output_bytes(transformed, args.transform_output_file)
    except (TransformError, ValueError, OSError) as exc:
        console.print(f"[red]Transform failed:[/red] {exc}")
        return 2
    console.print(f"Transform Output : {output}" if args.transform_output_file else output)
    return 0


def print_diff_result(diff: dict) -> None:
    summary = Table(title="Safe Binary Diff Summary")
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="white")
    for key in ["original_path", "modified_path", "original_sha256", "modified_sha256", "original_size", "modified_size", "size_delta", "changed_range_count", "truncated"]:
        summary.add_row(key, str(diff.get(key, "")))
    console.print(summary)


def print_recent(rows: list[dict]) -> None:
    table = Table(title="Recent Analyses")
    for column in ["ID", "Created", "Target", "Arch", "SHA256", "Risk", "VMProtect", "APIs", "Protector", "YARA"]:
        table.add_column(column)
    for row in rows:
        table.add_row(str(row["id"]), str(row["created_at"]), str(row["target_path"]), str(row["architecture"]), str(row["sha256"]), f"{row.get('risk_score', 0)} / {row.get('risk_severity', 'low')}", f"{row.get('vmprotect_classification', 'unknown')} / {row.get('vmprotect_confidence', 0)}", str(row["suspicious_api_count"]), str(row["protector_finding_count"]), str(row.get("yara_match_count", 0)))
    console.print(table)


def print_summary(result) -> None:
    vmp = result.vmprotect_profile or {}
    features = result.pe_features or {}
    tls = features.get("tls", {})
    crypto = result.crypto_analysis or {}
    problems = result.problem_locations or {}
    summary = Table(title="PE Analysis Summary")
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="white")
    rows = {
        "Path": result.path,
        "Size": f"{result.size:,} bytes",
        "SHA256": result.hashes.sha256,
        "Risk": f"{result.risk.get('score', 0)} / {result.risk.get('severity', 'low')}",
        "VMProtect": f"{vmp.get('classification', 'unknown')} / {vmp.get('confidence_score', 0)}",
        "Problem Locations": problems.get("location_count", 0),
        "EntryPoint Section": features.get("entry_point_section", ""),
        "Section Anomalies": features.get("section_anomaly_count", 0),
        "TLS": f"present={tls.get('present', False)}, callbacks={tls.get('callback_count', 0)}",
        "Crypto APIs": crypto.get("crypto_api_count", 0),
        "Crypto Constants": crypto.get("constant_count", 0),
        "Encoded Candidates": crypto.get("encoded_candidate_count", 0),
        "High Entropy Regions": crypto.get("high_entropy_region_count", 0),
        "YARA Matches": len(result.yara_matches),
        "Disassembly": f"{len(result.disassembly)} instruction(s)",
        "Data Coverage": f"{result.data_requirements.get('coverage_percent', 0)}%",
    }
    for key, value in rows.items():
        summary.add_row(key, str(value))
    console.print(summary)

    if problems.get("locations"):
        table = Table(title="Top Problem Locations")
        for column in ["Priority", "Category", "Title", "Address/Offset", "Section", "Reason", "Suggested Action"]:
            table.add_column(column)
        for item in problems.get("locations", [])[:15]:
            table.add_row(str(item.get("priority", "")), str(item.get("category", "")), str(item.get("title", "")), str(item.get("address_or_offset", "")), str(item.get("section", "")), str(item.get("reason", "")), str(item.get("suggested_action", "")))
        console.print(table)

    if vmp.get("evidence"):
        table = Table(title="VMProtect Evidence")
        for column in ["Points", "Severity", "Category", "Title", "Detail"]:
            table.add_column(column)
        for item in vmp.get("evidence", [])[:20]:
            table.add_row(str(item.get("points", 0)), str(item.get("severity", "")), str(item.get("category", "")), str(item.get("title", "")), str(item.get("detail", "")))
        console.print(table)

    if result.warnings:
        console.print("[yellow]Warnings[/yellow]")
        for warning in result.warnings:
            console.print(f"- {warning}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.dump_view:
        return run_dump_view_mode(args)
    if args.memdump:
        return run_memory_dump_mode(args)
    if args.pcap:
        return run_pcap_mode(args)
    if args.opcode_file or args.opcode_hex:
        return run_opcode_mode(args)
    if args.transform:
        return run_transform_mode(args)

    if args.diff_original or args.diff_modified:
        if not args.diff_original or not args.diff_modified:
            console.print("[red]Both --diff-original and --diff-modified are required for diff mode.[/red]")
            return 2
        try:
            diff = analyze_binary_diff(args.diff_original, args.diff_modified, max_ranges=max(args.diff_max_ranges, 1))
        except OSError as exc:
            console.print(f"[red]Failed to read diff input file:[/red] {exc}")
            return 4
        print_diff_result(diff)
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        diff_path = output_dir / "binary_diff.json"
        diff_path.write_text(json.dumps(diff, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"Diff JSON : {diff_path}")
        return 0

    db = AnalysisDatabase(args.db)
    if args.recent:
        rows = db.list_recent(limit=max(args.recent_limit, 1))
        print_recent(rows)
        return 0

    if not args.target:
        parser.print_help()
        return 0

    target = Path(args.target)
    output_dir = Path(args.out)
    if not target.exists():
        console.print(f"[red]Target file does not exist:[/red] {target}")
        return 2
    if not target.is_file():
        console.print(f"[red]Target is not a file:[/red] {target}")
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = PEAnalyzer().analyze(target, yara_rules=args.yara_rules, disassemble=args.disasm, disasm_limit=args.disasm_limit)
        report_paths = write_reports(result, output_dir)
        analysis_id = db.insert_analysis(result, report_paths)
    except pefile.PEFormatError as exc:
        console.print(f"[red]Invalid or unsupported PE file:[/red] {exc}")
        return 3
    except OSError as exc:
        console.print(f"[red]Failed to read or write file:[/red] {exc}")
        return 4

    console.print("[bold cyan]AIA Reverse Lab[/bold cyan]")
    print_summary(result)
    console.print("[green]Step 9.10 problem locator completed.[/green]")
    console.print(f"Analysis ID : {analysis_id}")
    console.print(f"Database    : {Path(args.db)}")
    console.print(f"JSON Report : {report_paths['json']}")
    console.print(f"HTML Report : {report_paths['html']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
