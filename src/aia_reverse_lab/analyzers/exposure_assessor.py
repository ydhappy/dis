from __future__ import annotations

from typing import Any


def assess_exposure(result) -> dict[str, Any]:
    """Assess defensive exposure and remediation opportunities.

    The score is a hardening score: higher is better. It does not exploit findings.
    """
    findings: list[dict[str, Any]] = []

    add_pe_hardening_findings(result, findings)
    add_import_surface_findings(result, findings)
    add_crypto_surface_findings(result, findings)
    add_protector_surface_findings(result, findings)
    add_strings_surface_findings(result, findings)
    add_problem_location_findings(result, findings)

    total_penalty = min(sum(int(item.get("penalty", 0)) for item in findings), 100)
    hardening_score = max(0, 100 - total_penalty)
    severity = severity_from_score(hardening_score)
    prioritized = sorted(findings, key=lambda item: item.get("penalty", 0), reverse=True)
    potential_gain = min(sum(int(item.get("remediation_gain", 0)) for item in prioritized), 100 - hardening_score)

    return {
        "hardening_score": hardening_score,
        "severity": severity,
        "finding_count": len(prioritized),
        "potential_score_gain": potential_gain,
        "findings": prioritized[:100],
        "top_remediation": build_top_remediation(prioritized),
        "score_model": "100 - exposure penalties. Higher is better.",
    }


def add_pe_hardening_findings(result, findings: list[dict[str, Any]]) -> None:
    features = result.pe_features or {}
    entry_perms = features.get("entry_point_section_permissions") or {}
    if entry_perms.get("rwx"):
        findings.append(finding(
            penalty=18,
            gain=18,
            severity="high",
            category="pe_permissions",
            title="EntryPoint section is RWX",
            evidence=str(entry_perms),
            remediation="Avoid RWX sections. Split writable data and executable code, and enable W^X where possible.",
        ))

    for anomaly in features.get("section_anomalies", [])[:30]:
        category = str(anomaly.get("category", "section_anomaly"))
        penalty = 12 if category in {"rwx_section", "entrypoint_high_entropy"} else 6
        findings.append(finding(
            penalty=penalty,
            gain=penalty,
            severity="high" if penalty >= 12 else "medium",
            category="section_anomaly",
            title=f"Section anomaly: {category}",
            evidence=f"section={anomaly.get('section')}, entropy={anomaly.get('entropy')}",
            remediation="Review section flags, entropy, raw/virtual size ratio, and whether the layout is expected for this build.",
        ))

    tls = features.get("tls", {})
    if tls.get("present"):
        callbacks = int(tls.get("callback_count", 0) or 0)
        penalty = 8 if callbacks else 4
        findings.append(finding(
            penalty=penalty,
            gain=penalty,
            severity="medium" if callbacks else "low",
            category="tls",
            title="TLS directory present",
            evidence=f"callback_count={callbacks}",
            remediation="Verify TLS callbacks are expected and documented. Unexpected TLS callbacks should be reviewed first.",
        ))


def add_import_surface_findings(result, findings: list[dict[str, Any]]) -> None:
    if result.import_count == 0:
        findings.append(finding(
            penalty=14,
            gain=10,
            severity="medium",
            category="imports",
            title="No import table detected",
            evidence="Import table is empty or unavailable.",
            remediation="For internal builds, preserve symbols/import metadata in diagnostic builds to improve auditability.",
        ))
    elif result.import_count <= 5:
        findings.append(finding(
            penalty=6,
            gain=4,
            severity="low",
            category="imports",
            title="Sparse import table",
            evidence=f"import_count={result.import_count}",
            remediation="Confirm whether sparse imports are expected, packed, or manually resolved.",
        ))

    dangerous_categories = {"process_injection", "memory_allocation", "network", "persistence"}
    for api in result.suspicious_apis[:50]:
        category = str(api.get("category", ""))
        severity = str(api.get("severity", "low"))
        if category not in dangerous_categories and severity == "low":
            continue
        penalty = {"high": 12, "medium": 8, "low": 4}.get(severity, 4)
        findings.append(finding(
            penalty=penalty,
            gain=max(2, penalty // 2),
            severity=severity,
            category=f"api:{category}",
            title=f"Sensitive API surface: {api.get('function', '')}",
            evidence=f"{api.get('dll', '')}!{api.get('function', '')}",
            remediation="Confirm this API is required. Add logging, validation, least-privilege checks, or remove unused capability.",
        ))


def add_crypto_surface_findings(result, findings: list[dict[str, Any]]) -> None:
    crypto = result.crypto_analysis or {}
    if crypto.get("encoded_candidate_count", 0):
        findings.append(finding(
            penalty=6,
            gain=6,
            severity="low",
            category="encoding",
            title="Encoded string candidates present",
            evidence=f"count={crypto.get('encoded_candidate_count', 0)}",
            remediation="Classify encoded strings as expected config/resource data or remove hardcoded encoded secrets/configuration.",
        ))
    if crypto.get("high_entropy_region_count", 0):
        findings.append(finding(
            penalty=10,
            gain=8,
            severity="medium",
            category="entropy",
            title="High entropy regions present",
            evidence=f"count={crypto.get('high_entropy_region_count', 0)}",
            remediation="Map high entropy regions to resources, compressed data, encrypted blobs, or packer output. Document expected regions.",
        ))
    if crypto.get("crypto_api_count", 0) and not crypto.get("constant_count", 0):
        findings.append(finding(
            penalty=3,
            gain=3,
            severity="info",
            category="crypto_api",
            title="Crypto API usage detected",
            evidence=f"count={crypto.get('crypto_api_count', 0)}",
            remediation="Verify modern algorithms, authenticated modes, safe key storage, and error handling in source review.",
        ))


def add_protector_surface_findings(result, findings: list[dict[str, Any]]) -> None:
    vmp = result.vmprotect_profile or {}
    classification = str(vmp.get("classification", ""))
    if classification in {"vmprotect_likely", "vmprotect_possible", "protected_or_packed_likely"}:
        penalty = 10 if classification == "vmprotect_likely" else 6
        findings.append(finding(
            penalty=penalty,
            gain=penalty,
            severity="medium",
            category="protector_profile",
            title=f"Protected/packed profile: {classification}",
            evidence=f"confidence={vmp.get('confidence_score', 0)}",
            remediation="Keep an unprotected internal diagnostic build for security review, crash triage, and reproducible diffing.",
        ))

    if result.anti_analysis_indicators:
        findings.append(finding(
            penalty=8,
            gain=6,
            severity="medium",
            category="anti_analysis",
            title="Anti-analysis indicators present",
            evidence=f"count={len(result.anti_analysis_indicators)}",
            remediation="Document anti-analysis logic in internal builds and ensure it does not block authorized diagnostics.",
        ))


def add_strings_surface_findings(result, findings: list[dict[str, Any]]) -> None:
    tagged = [item for item in result.strings if item.get("tags")]
    if tagged:
        findings.append(finding(
            penalty=min(12, len(tagged)),
            gain=min(10, len(tagged)),
            severity="medium" if len(tagged) >= 5 else "low",
            category="string_indicators",
            title="Tagged sensitive strings present",
            evidence=f"count={len(tagged)}",
            remediation="Review tagged strings for endpoints, commands, credentials, debug paths, or internal-only data.",
        ))


def add_problem_location_findings(result, findings: list[dict[str, Any]]) -> None:
    problems = result.problem_locations or {}
    count = int(problems.get("location_count", 0) or 0)
    if count >= 10:
        findings.append(finding(
            penalty=8,
            gain=8,
            severity="medium",
            category="triage_density",
            title="Many problem locations detected",
            evidence=f"count={count}",
            remediation="Resolve high-priority problem locations first, then re-run analysis to measure score gain.",
        ))


def finding(
    *,
    penalty: int,
    gain: int,
    severity: str,
    category: str,
    title: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "penalty": penalty,
        "remediation_gain": gain,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
    }


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "good"
    if score >= 70:
        return "watch"
    if score >= 50:
        return "weak"
    return "critical"


def build_top_remediation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in findings[:10]:
        items.append({
            "expected_gain": item.get("remediation_gain", 0),
            "title": item.get("title", ""),
            "remediation": item.get("remediation", ""),
        })
    return items
