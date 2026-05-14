from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from rich.console import Console
from rich.table import Table

from aia_reverse_lab import __version__
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
    parser.add_argument(
        "--out",
        default="reports",
        help="Output directory for analysis reports. Default: reports",
    )
    parser.add_argument(
        "--db",
        default="aia_reverse_lab.sqlite3",
        help="SQLite database path. Default: aia_reverse_lab.sqlite3",
    )
    parser.add_argument(
        "--yara-rules",
        default=None,
        help="Optional YARA rule file or directory to scan with.",
    )
    parser.add_argument(
        "--recent",
        action="store_true",
        help="Show recent analyses from the SQLite database and exit.",
    )
    parser.add_argument(
        "--recent-limit",
        type=int,
        default=20,
        help="Number of recent analyses to show with --recent. Default: 20",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"aia-reverse-lab {__version__}",
    )
    return parser


def print_recent(rows: list[dict]) -> None:
    table = Table(title="Recent Analyses")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Created", style="white")
    table.add_column("Target", style="white")
    table.add_column("Arch", style="green")
    table.add_column("SHA256", style="magenta")
    table.add_column("Suspicious APIs", style="red")
    table.add_column("Protector", style="yellow")
    table.add_column("YARA", style="magenta")

    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["created_at"]),
            str(row["target_path"]),
            str(row["architecture"]),
            str(row["sha256"]),
            str(row["suspicious_api_count"]),
            str(row["protector_finding_count"]),
            str(row.get("yara_match_count", 0)),
        )
    console.print(table)


def print_summary(result) -> None:
    summary = Table(title="PE Analysis Summary")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")

    summary.add_row("Path", result.path)
    summary.add_row("Size", f"{result.size:,} bytes")
    summary.add_row("SHA256", result.hashes.sha256)
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
    summary.add_row("Protector Findings", str(len(result.protector_findings)))
    summary.add_row("YARA Matches", str(len(result.yara_matches)))

    console.print(summary)

    if result.protector_findings:
        protector_table = Table(title="Protector / Packer Indicators")
        protector_table.add_column("Name", style="magenta")
        protector_table.add_column("Confidence", style="cyan")
        protector_table.add_column("Reason", style="white")
        for finding in result.protector_findings[:10]:
            protector_table.add_row(
                str(finding.get("name", "unknown")),
                str(finding.get("confidence", "unknown")),
                str(finding.get("reason", "")),
            )
        console.print(protector_table)

    if result.yara_matches:
        yara_table = Table(title="YARA Matches")
        yara_table.add_column("Rule", style="magenta")
        yara_table.add_column("Namespace", style="cyan")
        yara_table.add_column("Tags", style="white")
        yara_table.add_column("Strings", style="white")
        for item in result.yara_matches[:15]:
            yara_table.add_row(
                str(item.get("rule", "")),
                str(item.get("namespace", "")),
                ", ".join(item.get("tags", [])),
                str(item.get("string_match_count", 0)),
            )
        console.print(yara_table)

    if result.suspicious_apis:
        api_table = Table(title="Suspicious API Indicators")
        api_table.add_column("Severity", style="red")
        api_table.add_column("Category", style="cyan")
        api_table.add_column("DLL", style="white")
        api_table.add_column("Function", style="white")
        for item in result.suspicious_apis[:15]:
            api_table.add_row(
                item.get("severity", ""),
                item.get("category", ""),
                item.get("dll", ""),
                item.get("function", ""),
            )
        console.print(api_table)

    if result.warnings:
        console.print("[yellow]Warnings[/yellow]")
        for warning in result.warnings:
            console.print(f"- {warning}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
        result = PEAnalyzer().analyze(target, yara_rules=args.yara_rules)
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
    console.print("[green]Step 7 YARA scanning completed.[/green]")
    console.print(f"Analysis ID : {analysis_id}")
    console.print(f"Database    : {Path(args.db)}")
    console.print(f"JSON Report : {report_paths['json']}")
    console.print(f"HTML Report : {report_paths['html']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
