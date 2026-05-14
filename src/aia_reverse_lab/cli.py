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

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aia-reverse-lab",
        description="Defensive EXE/DLL binary analysis workbench",
    )
    parser.add_argument("target", nargs="?", help="Path to EXE/DLL file to analyze")
    parser.add_argument("--out", default="reports", help="Output directory for analysis reports. Default: reports")
    parser.add_argument("--db", default="aia_reverse_lab.sqlite3", help="SQLite database path. Default: aia_reverse_lab.sqlite3")
    parser.add_argument("--yara-rules", default=None, help="Optional YARA rule file or directory to scan with.")
    parser.add_argument("--disasm", action="store_true", help="Enable passive static EntryPoint disassembly using optional Capstone.")
    parser.add_argument("--disasm-limit", type=int, default=80, help="Maximum number of EntryPoint instructions to disassemble. Default: 80")
    parser.add_argument("--diff-original", default=None, help="Original authorized file for safe binary diff mode.")
    parser.add_argument("--diff-modified", default=None, help="Modified authorized file for safe binary diff mode.")
    parser.add_argument("--diff-max-ranges", type=int, default=200, help="Maximum changed ranges to report. Default: 200")
    parser.add_argument("--recent", action="store_true", help="Show recent analyses from the SQLite database and exit.")
    parser.add_argument("--recent-limit", type=int, default=20, help="Number of recent analyses to show with --recent. Default: 20")
    parser.add_argument("--version", action="version", version=f"aia-reverse-lab {__version__}")
    return parser


def print_diff_result(diff: dict) -> None:
    summary = Table(title="Safe Binary Diff Summary")
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="white")
    summary.add_row("Original", diff["original_path"])
    summary.add_row("Modified", diff["modified_path"])
    summary.add_row("Original SHA256", diff["original_sha256"])
    summary.add_row("Modified SHA256", diff["modified_sha256"])
    summary.add_row("Original Size", f"{diff['original_size']:,} bytes")
    summary.add_row("Modified Size", f"{diff['modified_size']:,} bytes")
    summary.add_row("Size Delta", str(diff["size_delta"]))
    summary.add_row("Changed Ranges", str(diff["changed_range_count"]))
    summary.add_row("Truncated", str(diff["truncated"]))
    console.print(summary)

    ranges = Table(title="Changed Ranges")
    ranges.add_column("Start", style="cyan")
    ranges.add_column("End", style="cyan")
    ranges.add_column("Length", style="white")
    ranges.add_column("Original Preview", style="red")
    ranges.add_column("Modified Preview", style="green")
    for item in diff["changed_ranges"][:30]:
        ranges.add_row(str(item["start_offset"]), str(item["end_offset_exclusive"]), str(item["length"]), str(item["original_preview"]), str(item["modified_preview"]))
    console.print(ranges)


def print_recent(rows: list[dict]) -> None:
    table = Table(title="Recent Analyses")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Created", style="white")
    table.add_column("Target", style="white")
    table.add_column("Arch", style="green")
    table.add_column("SHA256", style="magenta")
    table.add_column("Risk", style="red")
    table.add_column("Suspicious APIs", style="red")
    table.add_column("Protector", style="yellow")
    table.add_column("YARA", style="magenta")

    for row in rows:
        table.add_row(
            str(row["id"]), str(row["created_at"]), str(row["target_path"]), str(row["architecture"]), str(row["sha256"]),
            f"{row.get('risk_score', 0)} / {row.get('risk_severity', 'low')}", str(row["suspicious_api_count"]),
            str(row["protector_finding_count"]), str(row.get("yara_match_count", 0)),
        )
    console.print(table)


def print_summary(result) -> None:
    vmp = result.vmprotect_profile or {}
    summary = Table(title="PE Analysis Summary")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")

    summary.add_row("Path", result.path)
    summary.add_row("Size", f"{result.size:,} bytes")
    summary.add_row("SHA256", result.hashes.sha256)
    summary.add_row("Risk", f"{result.risk.get('score', 0)} / {result.risk.get('severity', 'low')}")
    summary.add_row("VMProtect", f"{vmp.get('classification', 'unknown')} / {vmp.get('confidence_score', 0)}")
    summary.add_row("Architecture", result.architecture)
    summary.add_row("Machine", result.machine)
    summary.add_row("Subsystem", result.subsystem)
    summary.add_row("Image Base", result.image_base)
    summary.add_row("Entry Point", result.entry_point)
    summary.add_row("Compile Time", result.compile_timestamp)
    summary.add_row("Sections", str(result.section_count))
    summary.add_row("Imports", str(result.import_count))
    summary.add_row("Exports", str(result.export_count))
    summary.add_row("Overlay", f"{result.overlay_size:,} bytes")
    summary.add_row("Strings", str(len(result.strings)))
    summary.add_row("Suspicious APIs", str(len(result.suspicious_apis)))
    summary.add_row("Anti-analysis", str(len(result.anti_analysis_indicators)))
    summary.add_row("Protector Findings", str(len(result.protector_findings)))
    summary.add_row("YARA Matches", str(len(result.yara_matches)))
    summary.add_row("Disassembly", f"{len(result.disassembly)} instruction(s)")
    summary.add_row("Flow Blocks", str(result.flow_summary.get("basic_block_count", 0)))
    summary.add_row("Data Coverage", f"{result.data_requirements.get('coverage_percent', 0)}%")
    console.print(summary)

    if vmp.get("evidence"):
        vmp_table = Table(title="VMProtect Profile Evidence")
        vmp_table.add_column("Points", style="red")
        vmp_table.add_column("Severity", style="yellow")
        vmp_table.add_column("Category", style="cyan")
        vmp_table.add_column("Title", style="white")
        vmp_table.add_column("Detail", style="white")
        for item in vmp.get("evidence", [])[:15]:
            vmp_table.add_row(str(item.get("points", 0)), str(item.get("severity", "")), str(item.get("category", "")), str(item.get("title", "")), str(item.get("detail", "")))
        console.print(vmp_table)
        if vmp.get("analyst_notes"):
            console.print(f"[cyan]VMProtect Note:[/cyan] {vmp.get('analyst_notes')}")

    risk_findings = result.risk.get("findings", [])
    if risk_findings:
        risk_table = Table(title="Risk Findings")
        risk_table.add_column("Points", style="red")
        risk_table.add_column("Severity", style="yellow")
        risk_table.add_column("Category", style="cyan")
        risk_table.add_column("Title", style="white")
        risk_table.add_column("Detail", style="white")
        for item in risk_findings[:15]:
            risk_table.add_row(str(item.get("points", 0)), str(item.get("severity", "")), str(item.get("category", "")), str(item.get("title", "")), str(item.get("detail", "")))
        console.print(risk_table)

    if result.anti_analysis_indicators:
        anti_table = Table(title="Anti-analysis Indicators")
        anti_table.add_column("Type", style="cyan")
        anti_table.add_column("Category", style="yellow")
        anti_table.add_column("Value", style="white")
        anti_table.add_column("Source", style="white")
        for item in result.anti_analysis_indicators[:20]:
            anti_table.add_row(str(item.get("type", "")), str(item.get("category", "")), str(item.get("value", "")), str(item.get("source", "")))
        console.print(anti_table)

    if result.flow_summary.get("available"):
        flow_table = Table(title="Static Flow Summary")
        flow_table.add_column("Metric", style="cyan")
        flow_table.add_column("Value", style="white")
        for key in ["instruction_count", "basic_block_count", "edge_count", "branch_count", "call_count", "return_count"]:
            flow_table.add_row(key, str(result.flow_summary.get(key, 0)))
        console.print(flow_table)

    if result.warnings:
        console.print("[yellow]Warnings[/yellow]")
        for warning in result.warnings:
            console.print(f"- {warning}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
    console.print("[green]Step 9.6 VMProtect profile analysis completed.[/green]")
    console.print(f"Analysis ID : {analysis_id}")
    console.print(f"Database    : {Path(args.db)}")
    console.print(f"JSON Report : {report_paths['json']}")
    console.print(f"HTML Report : {report_paths['html']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
