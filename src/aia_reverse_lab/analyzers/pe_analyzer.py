from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path

import pefile

from aia_reverse_lab.analyzers.api_classifier import classify_imports
from aia_reverse_lab.analyzers.disassembler import (
    CapstoneUnavailableError,
    UnsupportedArchitectureError,
    disassemble_entry_point,
)
from aia_reverse_lab.analyzers.protector_detector import detect_overlay_size, detect_protectors
from aia_reverse_lab.analyzers.risk_scorer import score_analysis
from aia_reverse_lab.analyzers.string_analyzer import extract_strings
from aia_reverse_lab.analyzers.yara_scanner import YaraUnavailableError, scan_with_yara
from aia_reverse_lab.models import (
    ExportInfo,
    FileHashes,
    ImportInfo,
    PEAnalysisResult,
    SectionInfo,
)


MACHINE_TYPES = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

SUBSYSTEM_TYPES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}


def calculate_hashes(path: Path) -> FileHashes:
    md5 = hashlib.md5()  # noqa: S324 - non-security hash for file identity only
    sha1 = hashlib.sha1()  # noqa: S324 - non-security hash for file identity only
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def decode_section_name(raw_name: bytes) -> str:
    return raw_name.rstrip(b"\x00").decode("utf-8", errors="replace") or "<empty>"


def timestamp_to_iso(timestamp: int) -> str:
    if timestamp <= 0:
        return "unknown"
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def machine_to_architecture(machine: int) -> str:
    if machine == 0x014C:
        return "x86"
    if machine == 0x8664:
        return "x64"
    if machine == 0xAA64:
        return "arm64"
    if machine in {0x01C0, 0x01C4}:
        return "arm"
    return "unknown"


class PEAnalyzer:
    """PE file analyzer for safe static metadata extraction."""

    def analyze(
        self,
        target: str | Path,
        yara_rules: str | Path | None = None,
        disassemble: bool = False,
        disasm_limit: int = 80,
    ) -> PEAnalysisResult:
        path = Path(target)
        warnings: list[str] = []
        file_size = path.stat().st_size
        hashes = calculate_hashes(path)
        pe = pefile.PE(str(path), fast_load=False)

        try:
            sections = self._extract_sections(pe)
            imports = self._extract_imports(pe)
            exports = self._extract_exports(pe)
            strings = extract_strings(path)
            suspicious_apis = classify_imports(imports)
            overlay_size = detect_overlay_size(pe, file_size)
            protector_findings = detect_protectors(sections, imports, strings, overlay_size)
            yara_matches: list[dict] = []
            disassembly: list[dict] = []

            if yara_rules:
                try:
                    yara_matches = scan_with_yara(path, yara_rules)
                except YaraUnavailableError as exc:
                    warnings.append(str(exc))

            if disassemble:
                try:
                    disassembly = disassemble_entry_point(path, instruction_limit=max(disasm_limit, 1))
                except (CapstoneUnavailableError, UnsupportedArchitectureError) as exc:
                    warnings.append(str(exc))

            risk = score_analysis(
                sections=sections,
                imports=imports,
                suspicious_apis=suspicious_apis,
                protector_findings=protector_findings,
                yara_matches=yara_matches,
                overlay_size=overlay_size,
                strings=strings,
                disassembly=disassembly,
            )

            machine_value = pe.FILE_HEADER.Machine
            subsystem_value = pe.OPTIONAL_HEADER.Subsystem
            image_base = pe.OPTIONAL_HEADER.ImageBase
            entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point_va = image_base + entry_point_rva

            if not imports:
                warnings.append("No import table was found or import table is empty.")
            if not sections:
                warnings.append("No sections were found.")
            if overlay_size:
                warnings.append(f"Overlay data detected: {overlay_size:,} bytes.")
            if protector_findings:
                warnings.append("Packer/protector indicators were detected.")
            if yara_matches:
                warnings.append(f"YARA matched {len(yara_matches)} rule(s).")
            if disassemble and not disassembly:
                warnings.append("Entry point disassembly did not return any instructions.")

            return PEAnalysisResult(
                path=str(path),
                size=file_size,
                hashes=hashes,
                machine=MACHINE_TYPES.get(machine_value, f"unknown-0x{machine_value:04X}"),
                architecture=machine_to_architecture(machine_value),
                subsystem=SUBSYSTEM_TYPES.get(subsystem_value, f"unknown-{subsystem_value}"),
                image_base=f"0x{image_base:X}",
                entry_point=f"0x{entry_point_va:X}",
                compile_timestamp=timestamp_to_iso(pe.FILE_HEADER.TimeDateStamp),
                section_count=len(sections),
                import_count=sum(len(item.functions) for item in imports),
                export_count=len(exports),
                overlay_size=overlay_size,
                sections=sections,
                imports=imports,
                exports=exports,
                strings=strings,
                suspicious_apis=suspicious_apis,
                protector_findings=protector_findings,
                yara_matches=yara_matches,
                disassembly=disassembly,
                risk=risk,
                warnings=warnings,
            )
        finally:
            pe.close()

    def _extract_sections(self, pe: pefile.PE) -> list[SectionInfo]:
        sections: list[SectionInfo] = []
        for section in pe.sections:
            raw_data = section.get_data()
            sections.append(
                SectionInfo(
                    name=decode_section_name(section.Name),
                    virtual_address=f"0x{section.VirtualAddress:X}",
                    virtual_size=int(section.Misc_VirtualSize),
                    raw_size=int(section.SizeOfRawData),
                    raw_pointer=f"0x{section.PointerToRawData:X}",
                    characteristics=f"0x{section.Characteristics:X}",
                    entropy=calculate_entropy(raw_data),
                )
            )
        return sections

    def _extract_imports(self, pe: pefile.PE) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "<unknown>"
            functions: list[str] = []
            for imported_symbol in entry.imports:
                if imported_symbol.name:
                    functions.append(imported_symbol.name.decode("utf-8", errors="replace"))
                else:
                    functions.append(f"ordinal_{imported_symbol.ordinal}")
            imports.append(ImportInfo(dll=dll_name, functions=functions))
        return imports

    def _extract_exports(self, pe: pefile.PE) -> list[ExportInfo]:
        exports: list[ExportInfo] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports

        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = symbol.name.decode("utf-8", errors="replace") if symbol.name else "<anonymous>"
            exports.append(
                ExportInfo(
                    name=name,
                    ordinal=int(symbol.ordinal) if symbol.ordinal is not None else None,
                    address=f"0x{symbol.address:X}",
                )
            )
        return exports
