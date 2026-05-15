from __future__ import annotations

from typing import Any

ANTI_ANALYSIS_APIS = {
    "debugger_detection": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "RtlQueryProcessHeapInformation",
        "RtlQueryProcessDebugInformation",
        "RtlQueryProcessBackTraceInformation",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "DebugBreak",
        "BreakPoint",
        "DbgBreakPoint",
        "DbgUiRemoteBreakin",
    },
    "debug_object_thread_context": {
        "NtQueryObject",
        "NtSetInformationThread",
        "NtGetContextThread",
        "GetThreadContext",
        "SetThreadContext",
        "SuspendThread",
        "ResumeThread",
    },
    "exception_based_detection": {
        "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
        "UnhandledExceptionFilter",
        "RaiseException",
    },
    "timing_checks": {
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "timeGetTime",
        "GetSystemTime",
        "GetLocalTime",
        "NtQueryPerformanceCounter",
        "RDTSC",
        "rdtsc",
    },
    "environment_checks": {
        "GetComputerNameA",
        "GetComputerNameW",
        "GetUserNameA",
        "GetUserNameW",
        "GetSystemInfo",
        "GetNativeSystemInfo",
        "GlobalMemoryStatusEx",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
    },
    "process_tool_awareness": {
        "CreateToolhelp32Snapshot",
        "Process32FirstA",
        "Process32FirstW",
        "Process32NextA",
        "Process32NextW",
        "Thread32First",
        "Thread32Next",
        "Module32FirstA",
        "Module32FirstW",
        "Module32NextA",
        "Module32NextW",
        "EnumProcesses",
        "EnumProcessModules",
    },
    "memory_integrity_checks": {
        "VirtualQuery",
        "VirtualQueryEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "ReadProcessMemory",
        "WriteProcessMemory",
        "FlushInstructionCache",
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
        "dbgview",
        "debugview",
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
        "hyperv",
        "xen",
    ],
    "analysis_tools": [
        "procmon",
        "procexp",
        "process hacker",
        "wireshark",
        "fiddler",
        "tcpview",
        "regshot",
        "scylla",
        "lordpe",
        "pe-bear",
        "pestudio",
        "die.exe",
    ],
    "anti_debug_terms": [
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
}

VMProtect_ANTI_DEBUG_NOTES = {
    "debugger_detection": "Classic debugger checks and ntdll process-information probes.",
    "debug_object_thread_context": "Debug object, thread hiding, or context manipulation related API surface.",
    "exception_based_detection": "Exception handler flow may be used for anti-debug control flow.",
    "timing_checks": "Timing probes may be used to detect breakpoints, stepping, or emulation overhead.",
    "environment_checks": "Environment and dynamic API lookup checks may support anti-analysis routing.",
    "process_tool_awareness": "Tool/process/module enumeration may support analysis-tool detection.",
    "memory_integrity_checks": "Memory query/protection changes may support self-integrity or breakpoint detection.",
}


def detect_anti_analysis(imports, strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []

    for imported_dll in imports:
        for function in imported_dll.functions:
            normalized = normalize_api_name(function)
            for category, api_names in ANTI_ANALYSIS_APIS.items():
                if normalized in {normalize_api_name(item) for item in api_names}:
                    indicators.append(
                        {
                            "type": "api",
                            "category": category,
                            "value": function,
                            "source": imported_dll.dll,
                            "description": VMProtect_ANTI_DEBUG_NOTES.get(
                                category,
                                f"Imported API may support {category.replace('_', ' ')}.",
                            ),
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
                            "description": "Extracted string references analysis tooling, anti-debug fields, or virtualized environments.",
                        }
                    )

    return deduplicate(indicators)


def normalize_api_name(value: str) -> str:
    return value.strip().lower().removeprefix("__imp_").removeprefix("_")


def summarize_anti_analysis(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for item in indicators:
        category = str(item.get("category", "unknown"))
        categories[category] = categories.get(category, 0) + 1
    return {
        "indicator_count": len(indicators),
        "category_counts": categories,
        "vmprotect_anti_debug_relevant": any(
            category in categories
            for category in {
                "debugger_detection",
                "debug_object_thread_context",
                "exception_based_detection",
                "timing_checks",
                "anti_debug_terms",
            }
        ),
    }


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
