from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from rich.console import Console
from rich.table import Table

from aia_reverse_lab import __version__
from aia_reverse_lab.analyzers.pe_analyzer import PEAnalyzer

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
        "--version",
        action="version",
        version=f"aia-reverse-lab {__version__}",
    )
    return parser


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

    console.print(summary)

    if result.warnings:
        console.print("[yellow]Warnings[/yellow]")
        for warning in result.warnings:
            console.print(f"- {warning}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
        result = PEAnalyzer().analyze(target)
    except pefile.PEFormatError as exc:
        console.print(f"[red]Invalid or unsupported PE file:[/red] {exc}")
        return 3
    except OSError as exc:
        console.print(f"[red]Failed to read target file:[/red] {exc}")
        return 4

    console.print("[bold cyan]AIA Reverse Lab[/bold cyan]")
    print_summary(result)
    console.print("[green]Step 3 PE core analysis completed.[/green]")
    console.print("[yellow]JSON/HTML report output will be added in Step 5.[/yellow]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
