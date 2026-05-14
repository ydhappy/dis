from __future__ import annotations

from typing import Any


def score_analysis(
    *,
    sections,
    imports,
    suspicious_apis: list[dict[str, str]],
    protector_findings: list[dict[str, Any]],
    yara_matches: list[dict[str, Any]],
    overlay_size: int,
    strings: list[dict[str, Any]],
    disassembly: list[dict[str, Any]],
    vmprotect_profile: dict[str, Any] | None = None,
    pe_features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score static analysis indicators into a defensive triage risk summary.

    The score is heuristic. It is intended for prioritization, not attribution or proof of malware.
    """
    pe_features = pe_features or {}
    findings: list[dict[str, Any]] = []
    score = 0

    high_entropy_sections = [section for section in sections if section.entropy >= 7.2]
    if high_entropy_sections:
        points = min(20, 8 + len(high_entropy_sections) * 4)
        score += points
        findings.append(build_finding(points, "medium", "packing", "High entropy section(s)", ", ".join(section.name for section in high_entropy_sections[:10])))

    entry_entropy = pe_features.get("entry_point_section_entropy")
    if isinstance(entry_entropy, (int, float)) and entry_entropy >= 7.2:
        score += 12
        findings.append(build_finding(12, "medium", "pe_layout", "EntryPoint section high entropy", f"EntryPoint section entropy is {entry_entropy}."))

    entry_permissions = pe_features.get("entry_point_section_permissions") or {}
    if entry_permissions.get("rwx"):
        score += 12
        findings.append(build_finding(12, "medium", "pe_layout", "EntryPoint section is RWX", str(entry_permissions)))

    tls = pe_features.get("tls", {})
    if tls.get("present"):
        points = 8 if int(tls.get("callback_count", 0) or 0) else 4
        score += points
        findings.append(build_finding(points, "low", "pe_layout", "TLS directory present", f"callback_count={tls.get('callback_count', 0)}"))

    section_anomalies = pe_features.get("section_anomalies", [])
    if section_anomalies:
        points = min(20, len(section_anomalies) * 4)
        score += points
        findings.append(build_finding(points, "medium", "pe_layout", "Section layout anomalies", f"{len(section_anomalies)} anomaly/anomalies detected."))

    import_count = sum(len(item.functions) for item in imports)
    if import_count == 0:
        score += 15
        findings.append(build_finding(15, "medium", "imports", "No imports detected", "Missing imports may indicate packing, manual loading, or malformed metadata."))
    elif import_count <= 5:
        score += 8
        findings.append(build_finding(8, "low", "imports", "Sparse import table", f"Only {import_count} imported function(s) detected."))

    if overlay_size > 0:
        points = 6 if overlay_size < 1024 * 64 else 12
        score += points
        findings.append(build_finding(points, "low" if points == 6 else "medium", "overlay", "Overlay data detected", f"Overlay size: {overlay_size:,} bytes."))

    for item in suspicious_apis:
        severity = item.get("severity", "low")
        category = item.get("category", "unknown")
        points = {"high": 10, "medium": 6, "low": 3}.get(severity, 3)
        if category == "process_injection":
            points += 5
        score += points
        findings.append(build_finding(points, severity, f"api:{category}", f"Suspicious API: {item.get('function', '')}", f"{item.get('dll', '')}!{item.get('function', '')}"))

    for finding in protector_findings:
        confidence = str(finding.get("confidence", "low"))
        points = {"high": 20, "medium": 12, "low": 6}.get(confidence, 6)
        score += points
        findings.append(build_finding(points, "high" if confidence == "high" else "medium" if confidence == "medium" else "low", "protector", f"Protector indicator: {finding.get('name', 'unknown')}", str(finding.get("reason", ""))))

    if vmprotect_profile:
        vmp_classification = str(vmprotect_profile.get("classification", ""))
        vmp_score = int(vmprotect_profile.get("confidence_score", 0) or 0)
        if vmp_classification == "vmprotect_likely":
            points = min(30, 15 + vmp_score // 5)
            score += points
            findings.append(build_finding(points, "high", "vmprotect", "VMProtect likely", f"VMProtect profile confidence score is {vmp_score}."))
        elif vmp_classification == "vmprotect_possible":
            points = min(18, 8 + vmp_score // 8)
            score += points
            findings.append(build_finding(points, "medium", "vmprotect", "VMProtect possible", f"VMProtect profile confidence score is {vmp_score}."))
        elif vmp_classification == "protected_or_packed_likely":
            points = min(15, 6 + vmp_score // 10)
            score += points
            findings.append(build_finding(points, "medium", "vmprotect", "Protected or packed likely", f"Protection profile confidence score is {vmp_score}."))

    if yara_matches:
        points = min(40, 20 + len(yara_matches) * 5)
        score += points
        findings.append(build_finding(points, "high", "yara", "YARA rule match", f"Matched {len(yara_matches)} rule(s)."))

    tagged_string_count = sum(1 for item in strings if item.get("tags"))
    if tagged_string_count:
        points = min(15, tagged_string_count)
        score += points
        findings.append(build_finding(points, "low" if points < 10 else "medium", "strings", "Tagged suspicious strings", f"{tagged_string_count} extracted string(s) matched triage keywords."))

    if has_dense_control_flow_markers(disassembly):
        score += 8
        findings.append(build_finding(8, "low", "disassembly", "EntryPoint branch density indicator", "EntryPoint window contains multiple branch/call instructions."))

    normalized_score = min(score, 100)
    severity = severity_from_score(normalized_score)
    return {"score": normalized_score, "severity": severity, "finding_count": len(findings), "findings": collapse_findings(findings)}


def build_finding(points: int, severity: str, category: str, title: str, detail: str) -> dict[str, Any]:
    return {"points": points, "severity": severity, "category": category, "title": title, "detail": detail}


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def has_dense_control_flow_markers(disassembly: list[dict[str, Any]]) -> bool:
    if not disassembly:
        return False
    branch_prefixes = ("j", "call", "ret", "loop")
    count = 0
    for instruction in disassembly[:80]:
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        if mnemonic.startswith(branch_prefixes):
            count += 1
    return count >= 8


def collapse_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    collapsed: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in sorted(findings, key=lambda item: item.get("points", 0), reverse=True):
        key = (str(finding.get("severity", "")), str(finding.get("category", "")), str(finding.get("title", "")))
        if key in seen:
            continue
        seen.add(key)
        collapsed.append(finding)
    return collapsed[:50]
