from __future__ import annotations

API_CATEGORIES = {
    "process_injection": {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "OpenProcess",
        "VirtualProtectEx",
    },
    "memory_manipulation": {
        "VirtualAlloc",
        "VirtualProtect",
        "HeapCreate",
        "HeapAlloc",
        "RtlMoveMemory",
        "memcpy",
    },
    "anti_debug": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "NtQueryInformationProcess",
        "GetTickCount",
        "QueryPerformanceCounter",
    },
    "persistence": {
        "RegCreateKeyA",
        "RegCreateKeyW",
        "RegSetValueA",
        "RegSetValueW",
        "RegSetValueExA",
        "RegSetValueExW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
    },
    "filesystem": {
        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "DeleteFileA",
        "DeleteFileW",
        "MoveFileA",
        "MoveFileW",
        "CopyFileA",
        "CopyFileW",
    },
    "network": {
        "socket",
        "connect",
        "send",
        "recv",
        "WSAStartup",
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpSendRequest",
    },
    "crypto": {
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptEncrypt",
        "CryptDecrypt",
        "BCryptEncrypt",
        "BCryptDecrypt",
    },
}


def classify_imports(imports) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for imported_dll in imports:
        for function in imported_dll.functions:
            for category, names in API_CATEGORIES.items():
                if function in names:
                    findings.append(
                        {
                            "dll": imported_dll.dll,
                            "function": function,
                            "category": category,
                            "severity": severity_for_category(category),
                        }
                    )
    return findings


def severity_for_category(category: str) -> str:
    if category in {"process_injection", "anti_debug"}:
        return "high"
    if category in {"persistence", "network", "crypto"}:
        return "medium"
    return "low"
