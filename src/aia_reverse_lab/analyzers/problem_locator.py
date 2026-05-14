from __future__ import annotations

from typing import Any


def locate_static_problems(result) -> dict[str, Any]:
    """Locate likely investigation points from safe static/offline analysis data."""
    locations: list[dict[str, Any]] = []

    add_entrypoint_locations(result, locations)
    add_section_anomaly_locations(result, locations)
    add_tls_locations(result, locations)
    add_crypto_locations(result, locations)
    add_vmprotect_locations(result, locations)
    add_yara_locations(result, locations)
    add_string_locations(result, locations)
    add_api_locations(result, locations)

    ranked = sorted(locations, key=lambda item: item.get("priority", 0), reverse=True)
    return {
        "location_count": len(ranked),
        "top_priority": ranked[0]["priority"] if ranked else 0,
        "locations": ranked[:100],
        "note": "Problem locations are triage hints from safe static/offline analysis. They are not bypass or patch instructions.",
    }


def add_entrypoint_locations(result, locations: list[dict[str, Any]]) -> None:
    features = result.pe_features or {}
    section = features.get("entry_point_section")
    entropy = features.get("entry_point_section_entropy")
    perms = features.get("entry_point_section_permissions") or {}
    if not section:
        return
    priority = 50
    reasons = [f"EntryPoint maps to section {section}"]
    if isinstance(entropy, (int, float)) and entropy >= 7.2:
        priority += 20
        reasons.append(f"high entropy {entropy}")
    if perms.get("rwx"):
        priority += 20
        reasons.append("RWX permissions")
    if str(section).lower().startswith(".vmp") or "vmp" in str(section).lower():
        priority += 25
        reasons.append("VMProtect-like section name")
    locations.append(
        build_location(
            priority=priority,
            category="entrypoint",
            title="Review EntryPoint section",
            address=result.entry_point,
            section=section,
            reason="; ".join(reasons),
            suggested_action="Inspect EntryPoint bytes, nearby disassembly, section permissions, and entropy.",
        )
    )


def add_section_anomaly_locations(result, locations: list[dict[str, Any]]) -> None:
    for anomaly in (result.pe_features or {}).get("section_anomalies", []):
        category = anomaly.get("category", "section_anomaly")
        priority = 55
        if category in {"rwx_section", "entrypoint_high_entropy", "entrypoint_non_executable"}:
            priority = 75
        locations.append(
            build_location(
                priority=priority,
                category="section_anomaly",
                title=f"Section anomaly: {category}",
                address=None,
                section=str(anomaly.get("section", "")),
                reason=str(anomaly.get("description", "")),
                suggested_action="Review section raw/virtual size, entropy, permissions, and whether it contains executable code.",
            )
        )


def add_tls_locations(result, locations: list[dict[str, Any]]) -> None:
    tls = (result.pe_features or {}).get("tls", {})
    if not tls.get("present"):
        return
    callbacks = tls.get("callbacks", [])
    priority = 65 if callbacks else 45
    locations.append(
        build_location(
            priority=priority,
            category="tls",
            title="Review TLS callbacks",
            address=str(tls.get("callback_array_va", "")),
            section=None,
            reason=f"TLS present with {tls.get('callback_count', 0)} callback(s).",
            suggested_action="Inspect TLS callback addresses and compare against expected compiler/runtime behavior.",
            extra={"callbacks": callbacks[:20]},
        )
    )


def add_crypto_locations(result, locations: list[dict[str, Any]]) -> None:
    crypto = result.crypto_analysis or {}
    for item in crypto.get("constants", [])[:30]:
        locations.append(
            build_location(
                priority=60,
                category="crypto_constant",
                title=f"Crypto marker: {item.get('name', '')}",
                address=str(item.get("offset", "")),
                section=None,
                reason="Crypto constants may indicate encryption, hashing, packing, or embedded crypto code.",
                suggested_action="Inspect surrounding bytes and cross-reference imports/strings.",
            )
        )
    for item in crypto.get("encoded_candidates", [])[:30]:
        locations.append(
            build_location(
                priority=45,
                category="encoded_candidate",
                title=f"Encoded candidate: {item.get('kind', '')}",
                address=str(item.get("offset", "")),
                section=None,
                reason=f"Encoded-looking string length={item.get('length')}; preview={item.get('preview')}",
                suggested_action="Use safe transform mode only when the encoding/key is known and authorized.",
            )
        )
    for item in crypto.get("high_entropy_regions", [])[:30]:
        locations.append(
            build_location(
                priority=50,
                category="high_entropy_region",
                title="High entropy region",
                address=str(item.get("offset", "")),
                section=None,
                reason=f"size={item.get('size')}, entropy={item.get('entropy')}",
                suggested_action="Review with dump viewer and compare against section layout or known packed/encrypted blobs.",
            )
        )


def add_vmprotect_locations(result, locations: list[dict[str, Any]]) -> None:
    vmp = result.vmprotect_profile or {}
    if not vmp:
        return
    classification = vmp.get("classification", "unknown")
    score = int(vmp.get("confidence_score", 0) or 0)
    if score:
        locations.append(
            build_location(
                priority=min(95, 50 + score // 2),
                category="vmprotect_profile",
                title=f"VMProtect profile: {classification}",
                address=result.entry_point,
                section=str(vmp.get("entry_point_section", "")),
                reason=f"confidence_score={score}; evidence_count={vmp.get('evidence_count', 0)}",
                suggested_action="Review VMProtect evidence and compare against authorized unprotected build if available.",
            )
        )
    for item in vmp.get("evidence", [])[:30]:
        points = int(item.get("points", 0) or 0)
        if points <= 0:
            continue
        locations.append(
            build_location(
                priority=min(90, 40 + points),
                category="vmprotect_evidence",
                title=str(item.get("title", "VMProtect evidence")),
                address=None,
                section=str(vmp.get("entry_point_section", "")),
                reason=str(item.get("detail", "")),
                suggested_action="Correlate this evidence with PE layout, opcode view, strings, and entropy.",
            )
        )


def add_yara_locations(result, locations: list[dict[str, Any]]) -> None:
    for match in result.yara_matches[:30]:
        locations.append(
            build_location(
                priority=80,
                category="yara",
                title=f"YARA match: {match.get('rule', '')}",
                address=None,
                section=None,
                reason=f"namespace={match.get('namespace', '')}, strings={match.get('string_match_count', 0)}",
                suggested_action="Review matched rule metadata and matched string offsets if present.",
            )
        )


def add_string_locations(result, locations: list[dict[str, Any]]) -> None:
    for item in result.strings[:300]:
        tags = item.get("tags") or []
        if not tags:
            continue
        locations.append(
            build_location(
                priority=40,
                category="string_indicator",
                title="Tagged string indicator",
                address=str(item.get("offset", "")),
                section=None,
                reason=f"tags={','.join(tags)}; value={str(item.get('value', ''))[:120]}",
                suggested_action="Inspect string references and nearby bytes.",
            )
        )


def add_api_locations(result, locations: list[dict[str, Any]]) -> None:
    for item in result.suspicious_apis[:100]:
        severity = item.get("severity", "low")
        priority = {"high": 75, "medium": 55, "low": 35}.get(severity, 35)
        locations.append(
            build_location(
                priority=priority,
                category="api_indicator",
                title=f"Suspicious API: {item.get('function', '')}",
                address=None,
                section=None,
                reason=f"{item.get('dll', '')}!{item.get('function', '')} category={item.get('category', '')}",
                suggested_action="Review import usage in code flow and determine whether it is expected for this binary.",
            )
        )


def build_location(
    *,
    priority: int,
    category: str,
    title: str,
    address: str | None,
    section: str | None,
    reason: str,
    suggested_action: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "priority": priority,
        "category": category,
        "title": title,
        "address_or_offset": address,
        "section": section,
        "reason": reason,
        "suggested_action": suggested_action,
    }
    if extra:
        payload["extra"] = extra
    return payload
