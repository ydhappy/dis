from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class FileHashes:
    md5: str
    sha1: str
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SectionInfo:
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    raw_pointer: str
    characteristics: str
    entropy: float
    executable: bool = False
    readable: bool = False
    writable: bool = False
    rwx: bool = False
    contains_entrypoint: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ImportInfo:
    dll: str
    functions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExportInfo:
    name: str
    ordinal: int | None
    address: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PEAnalysisResult:
    path: str
    size: int
    hashes: FileHashes
    machine: str
    architecture: str
    subsystem: str
    image_base: str
    entry_point: str
    compile_timestamp: str
    section_count: int
    import_count: int
    export_count: int
    overlay_size: int = 0
    pe_features: dict[str, Any] = field(default_factory=dict)
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    crypto_analysis: dict[str, Any] = field(default_factory=dict)
    suspicious_apis: list[dict[str, str]] = field(default_factory=list)
    protector_findings: list[dict[str, Any]] = field(default_factory=list)
    vmprotect_profile: dict[str, Any] = field(default_factory=dict)
    yara_matches: list[dict[str, Any]] = field(default_factory=list)
    disassembly: list[dict[str, Any]] = field(default_factory=list)
    flow_summary: dict[str, Any] = field(default_factory=dict)
    anti_analysis_indicators: list[dict[str, Any]] = field(default_factory=list)
    problem_locations: dict[str, Any] = field(default_factory=dict)
    exposure_assessment: dict[str, Any] = field(default_factory=dict)
    data_requirements: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "hashes": self.hashes.to_dict(),
            "machine": self.machine,
            "architecture": self.architecture,
            "subsystem": self.subsystem,
            "image_base": self.image_base,
            "entry_point": self.entry_point,
            "compile_timestamp": self.compile_timestamp,
            "section_count": self.section_count,
            "import_count": self.import_count,
            "export_count": self.export_count,
            "overlay_size": self.overlay_size,
            "pe_features": dict(self.pe_features),
            "sections": [section.to_dict() for section in self.sections],
            "imports": [item.to_dict() for item in self.imports],
            "exports": [item.to_dict() for item in self.exports],
            "strings": list(self.strings),
            "crypto_analysis": dict(self.crypto_analysis),
            "suspicious_apis": list(self.suspicious_apis),
            "protector_findings": list(self.protector_findings),
            "vmprotect_profile": dict(self.vmprotect_profile),
            "yara_matches": list(self.yara_matches),
            "disassembly": list(self.disassembly),
            "flow_summary": dict(self.flow_summary),
            "anti_analysis_indicators": list(self.anti_analysis_indicators),
            "problem_locations": dict(self.problem_locations),
            "exposure_assessment": dict(self.exposure_assessment),
            "data_requirements": dict(self.data_requirements),
            "risk": dict(self.risk),
            "warnings": list(self.warnings),
        }
