from __future__ import annotations

from typing import Any

ANTI_ANALYSIS_APIS = {
    "debugger_detection": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
    },
    "timing_checks": {
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "timeGetTime",
        "GetSystemTime",
        "GetLocalTime",
    },
    "environment_checks": {
        "GetComputerNameA",
        "GetComputerNameW",
        "GetUserNameA",
        "GetUserNameW",
        "GetSystemInfo",
        "GlobalMemoryStatusEx",
    },
    "process_tool_awareness": {
        "CreateToolhelp32Snapshot",
        "Process32FirstA",
        "Process32FirstW",
        "Process32NextA",
        "Process32NextW",
        "EnumProcesses",
    },
}

ANTI_ANALYSIS_STRING_KEYWORDS = {
    "debugger_names": [
        "x64dbg",
        "x32dbg",
        "ollydbg",
        "ida",
        "ida64",
        "windbg",
        "immunitydebugger",
    ],
    "vm_names": [
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "sandboxie",
        "wine",
        "parallels",
        "hyper-v",
    ],
    "analysis_tools": [
        "procmon",
        "procexp",
        "process hacker",
        "wireshark",
        "fiddler",
        "tcpview",
        "regshot",
    ],
}


def detect_anti_analysis(imports, strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []

    for imported_dll in imports:
        for function in imported_dll.functions:
            for category, api_names in ANTI_ANALYSIS_APIS.items():
                if function in api_names:
                    indicators.append(
                        {
                            "type": "api",
                            "category": category,
                            "value": function,
                            "source": imported_dll.dll,
                            "description": f"Imported API may support {category.replace('_', ' ')}.",
                        }
                    )

    for item in strings:
        value = str(item.get("value", ""))
        lowered = value.lower()
        for category, keywords in ANTI_ANALYSIS_STRING_KEYWORDS.items():
            for keyword in keywords:
                if keyword in lowered:
                    indicators.append(
                        {
                            "type": "string",
                            "category": category,
                            "value": keyword,
                            "source": item.get("offset", "unknown"),
                            "description": "Extracted string references analysis tooling or virtualized environments.",
                        }
                    )

    return deduplicate(indicators)


def deduplicate(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for indicator in indicators:
        key = (
            str(indicator.get("type", "")),
            str(indicator.get("category", "")),
            str(indicator.get("value", "")),
            str(indicator.get("source", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(indicator)
    return unique
