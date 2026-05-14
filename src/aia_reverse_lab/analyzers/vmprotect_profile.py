from __future__ import annotations

from typing import Any

VMP_SECTION_MARKERS = {
    ".vmp0",
    ".vmp1",
    ".vmp2",
    "vmp0",
    "vmp1",
    "vmp2",
    ".vmp",
    "vmp",
}

VMP_STRING_MARKERS = {
    "vmprotect",
    "vmpsoft",
    "vmp",
    "virtual machine protection",
}

VM_DISPATCHER_MNEMONICS = {
    "jmp",
    "call",
    "push",
    "pop",
    "xor",
    "rol",
    "ror",
    "shl",
    "shr",
    "and",
    "or",
}


def build_vmprotect_profile(
    *,
    sections,
    imports,
    strings: list[dict[str, Any]],
    protector_findings: list[dict[str, Any]],
    anti_analysis_indicators: list[dict[str, Any]],
    disassembly: list[dict[str, Any]],
    entry_point: str,
    overlay_size: int,
) -> dict[str, Any]:
    """Build a VMProtect-aware static profile without unpacking or bypassing protections."""
    evidence: list[dict[str, Any]] = []
    score = 0

    section_names = {section.name.lower(): section for section in sections}
    vmp_sections = [name for name in section_names if name in VMP_SECTION_MARKERS]
    if vmp_sections:
        points = 40
        score += points
        evidence.append(evidence_item(points, "high", "section_marker", "VMProtect-like section name", ", ".join(vmp_sections)))

    high_entropy = [section for section in sections if section.entropy >= 7.2]
    if high_entropy:
        points = min(20, 8 + len(high_entropy) * 4)
        score += points
        evidence.append(
            evidence_item(
                points,
                "medium",
                "entropy",
                "High entropy section correlation",
                ", ".join(f"{section.name}:{section.entropy}" for section in high_entropy[:8]),
            )
        )

    import_count = sum(len(item.functions) for item in imports)
    if import_count <= 5:
        points = 12
        score += points
        evidence.append(
            evidence_item(
                points,
                "medium",
                "imports",
                "Sparse import table",
                f"Import count is {import_count}.",
            )
        )

    string_hits = collect_string_hits(strings)
    if string_hits:
        points = 15
        score += points
        evidence.append(
            evidence_item(
                points,
                "medium",
                "strings",
                "VMProtect-related string marker",
                ", ".join(string_hits[:10]),
            )
        )

    protector_hits = [finding for finding in protector_findings if "vmprotect" in str(finding.get("name", "")).lower()]
    if protector_hits:
        points = 25
        score += points
        evidence.append(
            evidence_item(
                points,
                "high",
                "protector_detector",
                "Existing protector detector flagged VMProtect",
                "; ".join(str(item.get("reason", "")) for item in protector_hits[:5]),
            )
        )

    if overlay_size > 1024 * 64:
        points = 6
        score += points
        evidence.append(
            evidence_item(
                points,
                "low",
                "overlay",
                "Large overlay correlation",
                f"Overlay size is {overlay_size:,} bytes.",
            )
        )

    if anti_analysis_indicators:
        points = min(12, 4 + len(anti_analysis_indicators))
        score += points
        evidence.append(
            evidence_item(
                points,
                "medium",
                "anti_analysis",
                "Anti-analysis indicator correlation",
                f"{len(anti_analysis_indicators)} anti-analysis indicator(s) detected.",
            )
        )

    dispatcher_score = estimate_vm_dispatcher_pattern(disassembly)
    if dispatcher_score["score"]:
        score += dispatcher_score["score"]
        evidence.append(
            evidence_item(
                dispatcher_score["score"],
                dispatcher_score["severity"],
                "entrypoint_disassembly",
                "VM dispatcher-like EntryPoint instruction mix",
                dispatcher_score["detail"],
            )
        )

    entry_section = find_entrypoint_section(sections, entry_point)
    if entry_section:
        evidence.append(
            evidence_item(
                0,
                "info",
                "entrypoint_section",
                "EntryPoint section",
                f"EntryPoint appears to be in section {entry_section}.",
            )
        )

    confidence_score = min(score, 100)
    classification = classify(confidence_score, bool(vmp_sections), bool(protector_hits))
    return {
        "enabled": True,
        "classification": classification,
        "confidence_score": confidence_score,
        "evidence_count": len(evidence),
        "evidence": evidence,
        "analyst_notes": build_analyst_notes(classification),
        "safe_next_steps": [
            "Review section entropy and section names.",
            "Review EntryPoint disassembly and flow summary.",
            "Compare with an authorized unprotected build using safe binary diff mode.",
            "Run YARA rules for known packer/protector indicators.",
            "Execute only inside an isolated lab if dynamic behavior analysis is required.",
        ],
    }


def collect_string_hits(strings: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for item in strings:
        value = str(item.get("value", ""))
        lowered = value.lower()
        for marker in VMP_STRING_MARKERS:
            if marker in lowered:
                hits.append(f"{marker}@{item.get('offset', 'unknown')}")
    return hits


def estimate_vm_dispatcher_pattern(disassembly: list[dict[str, Any]]) -> dict[str, Any]:
    if not disassembly:
        return {"score": 0, "severity": "info", "detail": "No disassembly available."}

    window = disassembly[:80]
    mnemonic_counts: dict[str, int] = {}
    for instruction in window:
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        mnemonic_counts[mnemonic] = mnemonic_counts.get(mnemonic, 0) + 1

    dispatcher_like_count = sum(mnemonic_counts.get(item, 0) for item in VM_DISPATCHER_MNEMONICS)
    branch_count = sum(count for mnemonic, count in mnemonic_counts.items() if mnemonic.startswith("j") or mnemonic in {"jmp", "call"})
    ratio = dispatcher_like_count / len(window) if window else 0.0

    if ratio >= 0.45 and branch_count >= 8:
        return {
            "score": 14,
            "severity": "medium",
            "detail": f"Dispatcher-like mnemonic ratio={ratio:.2f}, branch/call count={branch_count}.",
        }
    if ratio >= 0.35 and branch_count >= 5:
        return {
            "score": 8,
            "severity": "low",
            "detail": f"Moderate dispatcher-like mnemonic ratio={ratio:.2f}, branch/call count={branch_count}.",
        }
    return {
        "score": 0,
        "severity": "info",
        "detail": f"Dispatcher-like mnemonic ratio={ratio:.2f}, branch/call count={branch_count}.",
    }


def find_entrypoint_section(sections, entry_point: str) -> str | None:
    try:
        entry_va = int(entry_point, 16)
    except ValueError:
        return None

    # Sections hold RVAs, not VAs. Without image base here, only provide a best-effort tag when names are known.
    # The exact mapping is already covered by PE metadata and future richer PE layout modeling.
    for section in sections:
        if section.name.lower() in VMP_SECTION_MARKERS:
            return section.name
    return None


def evidence_item(points: int, severity: str, category: str, title: str, detail: str) -> dict[str, Any]:
    return {
        "points": points,
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
    }


def classify(score: int, has_vmp_section: bool, has_detector_hit: bool) -> str:
    if has_vmp_section or (has_detector_hit and score >= 45):
        return "vmprotect_likely"
    if score >= 60:
        return "protected_or_packed_likely"
    if score >= 35:
        return "vmprotect_possible"
    return "no_strong_vmprotect_signal"


def build_analyst_notes(classification: str) -> str:
    if classification == "vmprotect_likely":
        return "Strong VMProtect indicators were found. This profile is for triage/reporting only and does not unpack or bypass protection."
    if classification == "vmprotect_possible":
        return "Some VMProtect-like indicators were found. Correlate with YARA results, section layout, and authorized build comparison."
    if classification == "protected_or_packed_likely":
        return "The binary appears packed/protected, but current evidence is not VMProtect-specific."
    return "Current static indicators do not strongly suggest VMProtect."
