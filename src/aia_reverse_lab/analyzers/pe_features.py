from __future__ import annotations

from typing import Any

import pefile

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def decode_section_permissions(characteristics: int) -> dict[str, bool]:
    return {
        "executable": bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
        "readable": bool(characteristics & IMAGE_SCN_MEM_READ),
        "writable": bool(characteristics & IMAGE_SCN_MEM_WRITE),
        "rwx": bool(
            (characteristics & IMAGE_SCN_MEM_EXECUTE)
            and (characteristics & IMAGE_SCN_MEM_READ)
            and (characteristics & IMAGE_SCN_MEM_WRITE)
        ),
    }


def build_pe_features(pe: pefile.PE, sections, entry_point_rva: int, image_base: int) -> dict[str, Any]:
    entry_section = find_section_by_rva(sections, entry_point_rva)
    section_anomalies = find_section_anomalies(sections, entry_point_rva)
    data_directories = extract_data_directories(pe)
    tls_info = extract_tls_info(pe, image_base)

    return {
        "entry_point_rva": f"0x{entry_point_rva:X}",
        "entry_point_section": entry_section["name"] if entry_section else None,
        "entry_point_section_entropy": entry_section["entropy"] if entry_section else None,
        "entry_point_section_permissions": entry_section["permissions"] if entry_section else {},
        "section_anomaly_count": len(section_anomalies),
        "section_anomalies": section_anomalies,
        "data_directories": data_directories,
        "tls": tls_info,
    }


def find_section_by_rva(sections, rva: int) -> dict[str, Any] | None:
    for section in sections:
        start = int(section.virtual_address, 16)
        size = max(int(section.virtual_size), int(section.raw_size), 1)
        end = start + size
        if start <= rva < end:
            return {
                "name": section.name,
                "start_rva": f"0x{start:X}",
                "end_rva": f"0x{end:X}",
                "entropy": section.entropy,
                "permissions": {
                    "executable": section.executable,
                    "readable": section.readable,
                    "writable": section.writable,
                    "rwx": section.rwx,
                },
            }
    return None


def find_section_anomalies(sections, entry_point_rva: int) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    for section in sections:
        if section.rwx:
            anomalies.append(section_anomaly(section, "rwx_section", "Section is readable, writable, and executable."))
        if section.executable and section.entropy >= 7.2:
            anomalies.append(section_anomaly(section, "executable_high_entropy", "Executable section has high entropy."))
        if section.executable and section.raw_size == 0 and section.virtual_size > 0:
            anomalies.append(section_anomaly(section, "executable_virtual_only", "Executable section has virtual size but no raw data."))
        if section.raw_size > 0 and section.virtual_size / max(section.raw_size, 1) >= 8:
            anomalies.append(section_anomaly(section, "large_virtual_raw_ratio", "Section virtual size is much larger than raw size."))
        if section.contains_entrypoint and not section.executable:
            anomalies.append(section_anomaly(section, "entrypoint_non_executable", "EntryPoint maps to a non-executable section."))
        if section.contains_entrypoint and section.entropy >= 7.2:
            anomalies.append(section_anomaly(section, "entrypoint_high_entropy", "EntryPoint section has high entropy."))
    return anomalies


def section_anomaly(section, category: str, description: str) -> dict[str, Any]:
    return {
        "section": section.name,
        "category": category,
        "description": description,
        "entropy": section.entropy,
        "permissions": {
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "rwx": section.rwx,
        },
    }


def extract_data_directories(pe: pefile.PE) -> list[dict[str, Any]]:
    directories: list[dict[str, Any]] = []
    for directory in getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", []):
        name = getattr(directory, "name", "UNKNOWN")
        virtual_address = int(getattr(directory, "VirtualAddress", 0))
        size = int(getattr(directory, "Size", 0))
        directories.append(
            {
                "name": str(name).replace("IMAGE_DIRECTORY_ENTRY_", ""),
                "rva": f"0x{virtual_address:X}",
                "size": size,
                "present": bool(virtual_address and size),
            }
        )
    return directories


def extract_tls_info(pe: pefile.PE, image_base: int) -> dict[str, Any]:
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return {"present": False, "callback_count": 0, "callbacks": []}

    callbacks: list[str] = []
    struct = pe.DIRECTORY_ENTRY_TLS.struct
    callback_array_va = int(getattr(struct, "AddressOfCallBacks", 0) or 0)
    if callback_array_va:
        try:
            callback_array_rva = callback_array_va - image_base
            offset = pe.get_offset_from_rva(callback_array_rva)
            pointer_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
            while True:
                raw = pe.__data__[offset : offset + pointer_size]
                if len(raw) < pointer_size:
                    break
                value = int.from_bytes(raw, "little")
                if value == 0:
                    break
                callbacks.append(f"0x{value:X}")
                offset += pointer_size
                if len(callbacks) >= 64:
                    break
        except Exception:
            callbacks.append("<failed_to_parse_callbacks>")

    return {
        "present": True,
        "callback_array_va": f"0x{callback_array_va:X}" if callback_array_va else None,
        "callback_count": len(callbacks),
        "callbacks": callbacks,
    }
