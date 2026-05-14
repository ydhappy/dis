from __future__ import annotations

KNOWN_PACKER_SECTION_NAMES = {
    "upx0": "UPX",
    "upx1": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack/Armadillo-like",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    "vmp0": "VMProtect",
    "vmp1": "VMProtect",
    "vmp2": "VMProtect",
    ".themida": "Themida/WinLicense",
    ".winlice": "Themida/WinLicense",
}

VM_PROTECT_KEYWORDS = {
    "vmprotect",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    "vmp0",
    "vmp1",
    "vmp2",
}


def detect_overlay_size(pe, file_size: int) -> int:
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:  # pragma: no cover - defensive parsing guard
        overlay_offset = None
    if overlay_offset is None:
        return 0
    if overlay_offset < 0 or overlay_offset > file_size:
        return 0
    return file_size - overlay_offset


def detect_protectors(sections, imports, strings, overlay_size: int) -> list[dict[str, object]]:
    """Detect packer/protector indicators using passive heuristics only."""
    findings: list[dict[str, object]] = []
    section_names = {section.name.lower() for section in sections}
    high_entropy_sections = [section.name for section in sections if section.entropy >= 7.2]
    import_count = sum(len(item.functions) for item in imports)

    for section_name in sorted(section_names):
        if section_name in KNOWN_PACKER_SECTION_NAMES:
            findings.append(
                {
                    "name": KNOWN_PACKER_SECTION_NAMES[section_name],
                    "confidence": "high",
                    "reason": f"Known packer/protector section name: {section_name}",
                }
            )

    if high_entropy_sections:
        findings.append(
            {
                "name": "Packed or encrypted section",
                "confidence": "medium",
                "reason": "High entropy section(s): " + ", ".join(high_entropy_sections[:10]),
            }
        )

    if import_count <= 5:
        findings.append(
            {
                "name": "Sparse import table",
                "confidence": "medium",
                "reason": f"Import table contains only {import_count} imported function(s)",
            }
        )

    if overlay_size > 1024 * 64:
        findings.append(
            {
                "name": "Large overlay",
                "confidence": "low",
                "reason": f"Overlay size is {overlay_size:,} bytes",
            }
        )

    joined_strings = "\n".join(str(item.get("value", "")).lower() for item in strings[:2000])
    if any(keyword in joined_strings for keyword in VM_PROTECT_KEYWORDS):
        findings.append(
            {
                "name": "VMProtect",
                "confidence": "medium",
                "reason": "VMProtect-related marker found in strings or metadata",
            }
        )

    if section_names.intersection(VM_PROTECT_KEYWORDS):
        findings.append(
            {
                "name": "VMProtect",
                "confidence": "high",
                "reason": "VMProtect-like section name detected",
            }
        )

    return deduplicate_findings(findings)


def deduplicate_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object]] = set()
    unique: list[dict[str, object]] = []
    for finding in findings:
        key = (finding.get("name"), finding.get("confidence"), finding.get("reason"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
