from __future__ import annotations

import re
from pathlib import Path

ASCII_PATTERN = re.compile(rb"[\x20-\x7E]{4,}")
UTF16LE_PATTERN = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")

SUSPICIOUS_STRING_KEYWORDS = {
    "url": ["http://", "https://", "ftp://", "ws://", "wss://"],
    "script": [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "bitsadmin",
    ],
    "registry": [
        "hkey_current_user",
        "hkey_local_machine",
        "\\software\\microsoft\\windows",
        "currentversion\\run",
        "currentversion\\runonce",
        "services\\",
    ],
    "credential": [
        "password",
        "passwd",
        "token",
        "apikey",
        "api_key",
        "secret",
        "private_key",
        "bearer ",
        "authorization:",
    ],
    "network": [
        "user-agent",
        "socket",
        "connect",
        "download",
        "upload",
        "winhttp",
        "wininet",
        "internetopen",
        "httpsendrequest",
    ],
    "anti_analysis": [
        "debugger",
        "ollydbg",
        "x64dbg",
        "x32dbg",
        "wireshark",
        "procmon",
        "procexp",
        "process hacker",
        "ida",
        "ida64",
        "windbg",
        "immunitydebugger",
        "dbgview",
        "scylla",
        "pestudio",
        "pe-bear",
    ],
    "anti_debug_fields": [
        "beingdebugged",
        "ntglobalflag",
        "processdebugport",
        "processdebugflags",
        "processdebugobjecthandle",
        "heapflags",
        "heapforceflags",
        "debugobject",
        "debugport",
        "trap flag",
        "single step",
    ],
    "vm_sandbox": [
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "sandboxie",
        "wine",
        "parallels",
        "hyper-v",
        "hyperv",
        "xen",
        "cuckoo",
        "any.run",
        "joesandbox",
    ],
    "loader_resolution": [
        "loadlibrary",
        "loadlibraryex",
        "getprocaddress",
        "ldrloaddll",
        "ldrgetprocedureaddress",
        "ldrgetdllhandle",
        "manualmap",
        "manual map",
        "reflective",
    ],
    "process_injection_terms": [
        "createremotethread",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "queueuserapc",
        "setwindowshookex",
        "writeprocessmemory",
        "readprocessmemory",
        "virtualallocex",
        "virtualprotectex",
        "ntmapviewofsection",
        "process hollowing",
        "runpe",
    ],
    "driver_kernel_terms": [
        "deviceiocontrol",
        "ntloaddriver",
        "zwloaddriver",
        "kernelmode",
        "kernel-mode",
        "driverobject",
        "irp_mj_device_control",
        "ioctl",
        "\\\\.\\",
    ],
    "protector_packer": [
        "vmprotect",
        "vmpsoft",
        "themida",
        "winlicense",
        "enigma protector",
        "upx",
        "asprotect",
        "obsidium",
        "mpress",
    ],
    "crypto_material": [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin certificate-----",
        "aes",
        "rsa",
        "sha256",
        "bcrypt",
        "ncrypt",
        "cryptdecrypt",
        "cryptencrypt",
    ],
}

TAG_SEVERITY = {
    "credential": "high",
    "process_injection_terms": "high",
    "driver_kernel_terms": "high",
    "anti_debug_fields": "medium",
    "anti_analysis": "medium",
    "vm_sandbox": "medium",
    "loader_resolution": "medium",
    "protector_packer": "medium",
    "crypto_material": "medium",
    "script": "medium",
    "registry": "medium",
    "network": "medium",
    "url": "low",
}


def classify_string(value: str) -> list[str]:
    lowered = value.lower()
    tags: list[str] = []
    for tag, needles in SUSPICIOUS_STRING_KEYWORDS.items():
        if any(needle in lowered for needle in needles):
            tags.append(tag)
    return tags


def classify_string_details(value: str) -> list[dict[str, str]]:
    lowered = value.lower()
    details: list[dict[str, str]] = []
    for tag, needles in SUSPICIOUS_STRING_KEYWORDS.items():
        for needle in needles:
            if needle in lowered:
                details.append(
                    {
                        "tag": tag,
                        "needle": needle,
                        "severity": TAG_SEVERITY.get(tag, "low"),
                    }
                )
    return details


def extract_strings(path: str | Path, limit: int = 2000) -> list[dict[str, object]]:
    """Extract printable ASCII and UTF-16LE strings from a file.

    This function performs passive string extraction only. It does not execute or modify the target.
    """
    data = Path(path).read_bytes()
    results: list[dict[str, object]] = []

    for match in ASCII_PATTERN.finditer(data):
        value = match.group().decode("utf-8", errors="replace")
        results.append(
            {
                "type": "ascii",
                "offset": f"0x{match.start():X}",
                "value": value,
                "tags": classify_string(value),
                "tag_details": classify_string_details(value),
            }
        )
        if len(results) >= limit:
            return results

    for match in UTF16LE_PATTERN.finditer(data):
        value = match.group().decode("utf-16le", errors="replace")
        results.append(
            {
                "type": "utf16le",
                "offset": f"0x{match.start():X}",
                "value": value,
                "tags": classify_string(value),
                "tag_details": classify_string_details(value),
            }
        )
        if len(results) >= limit:
            return results

    return results
