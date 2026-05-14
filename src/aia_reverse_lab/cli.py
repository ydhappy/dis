from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from aia_reverse_lab import __version__

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

    output_dir.mkdir(parents=True, exist_ok=True)

    console.print("[bold cyan]AIA Reverse Lab[/bold cyan]")
    console.print(f"Target : {target}")
    console.print(f"Output : {output_dir}")
    console.print("[yellow]Analyzer core will be added in Step 3.[/yellow]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
