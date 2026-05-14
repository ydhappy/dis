from __future__ import annotations

from typing import Any


def analyze_required_data(result) -> dict[str, Any]:
    """Report which analysis data categories are present or missing."""
    checks = [
        check("file_hashes", bool(result.hashes.sha256), "File hashes are available."),
        check("pe_headers", bool(result.machine and result.entry_point), "PE metadata is available."),
        check("pe_features", bool(result.pe_features), "Rich PE layout features are available."),
        check(
            "entrypoint_section",
            bool(result.pe_features.get("entry_point_section")),
            "EntryPoint-to-section mapping is available.",
        ),
        check(
            "section_anomalies",
            bool(result.pe_features.get("section_anomalies")),
            "Section anomaly analysis was generated.",
        ),
        check(
            "tls_analysis",
            "tls" in result.pe_features,
            "TLS directory analysis was generated.",
        ),
        check("sections", bool(result.sections), "Section table is available."),
        check("imports", bool(result.imports), "Import table is available."),
        check("exports", bool(result.exports), "Export table is available."),
        check("strings", bool(result.strings), "Static strings were extracted."),
        check("suspicious_apis", bool(result.suspicious_apis), "Suspicious API indicators were found."),
        check("protector_findings", bool(result.protector_findings), "Protector/packer indicators were found."),
        check("vmprotect_profile", bool(result.vmprotect_profile), "VMProtect profile analysis was generated."),
        check("vmprotect_evidence", bool(result.vmprotect_profile.get("evidence")), "VMProtect-specific evidence was found."),
        check("yara_matches", bool(result.yara_matches), "YARA rules matched, if rules were supplied."),
        check("disassembly", bool(result.disassembly), "EntryPoint disassembly is available."),
        check("flow_summary", bool(result.flow_summary.get("available")), "Static flow summary is available."),
        check("anti_analysis", bool(result.anti_analysis_indicators), "Anti-analysis indicators were found."),
        check("risk", bool(result.risk), "Risk score is available."),
    ]
    present = sum(1 for item in checks if item["present"])
    missing = len(checks) - present
    return {
        "present_count": present,
        "missing_count": missing,
        "coverage_percent": round((present / len(checks)) * 100, 2) if checks else 0.0,
        "checks": checks,
    }


def check(name: str, present: bool, description: str) -> dict[str, Any]:
    return {"name": name, "present": present, "description": description}
