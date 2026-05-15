from __future__ import annotations

API_CATEGORIES = {
    "process_handle_access": {
        "OpenProcess",
        "NtOpenProcess",
        "ZwOpenProcess",
        "OpenThread",
        "NtOpenThread",
        "ZwOpenThread",
        "DuplicateHandle",
        "NtDuplicateObject",
        "ZwDuplicateObject",
    },
    "process_injection": {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "ZwCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "ZwQueueApcThread",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "NtMapViewOfSection",
        "ZwMapViewOfSection",
        "CreateProcessA",
        "CreateProcessW",
        "CreateProcessInternalA",
        "CreateProcessInternalW",
    },
    "remote_memory_manipulation": {
        "ReadProcessMemory",
        "WriteProcessMemory",
        "VirtualQueryEx",
        "VirtualProtectEx",
        "VirtualAllocEx",
        "VirtualFreeEx",
        "NtReadVirtualMemory",
        "ZwReadVirtualMemory",
        "NtWriteVirtualMemory",
        "ZwWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "ZwProtectVirtualMemory",
        "NtAllocateVirtualMemory",
        "ZwAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "ZwFreeVirtualMemory",
    },
    "local_memory_manipulation": {
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualQuery",
        "VirtualFree",
        "HeapCreate",
        "HeapAlloc",
        "HeapReAlloc",
        "HeapFree",
        "RtlMoveMemory",
        "RtlCopyMemory",
        "memcpy",
        "memmove",
        "FlushInstructionCache",
    },
    "native_loader_resolution": {
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
        "LdrGetDllHandle",
        "LdrUnloadDll",
        "LdrEnumerateLoadedModules",
    },
    "thread_context_control": {
        "SuspendThread",
        "ResumeThread",
        "GetThreadContext",
        "SetThreadContext",
        "Wow64GetThreadContext",
        "Wow64SetThreadContext",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtSuspendThread",
        "NtResumeThread",
        "NtAlertThread",
        "NtContinue",
    },
    "anti_debug": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "NtQueryObject",
        "ZwQueryObject",
        "NtSetInformationThread",
        "ZwSetInformationThread",
        "RtlQueryProcessHeapInformation",
        "RtlQueryProcessDebugInformation",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "NtQueryPerformanceCounter",
        "timeGetTime",
        "DebugBreak",
        "RaiseException",
        "AddVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
    },
    "driver_kernel_surface": {
        "CreateFileA",
        "CreateFileW",
        "DeviceIoControl",
        "NtDeviceIoControlFile",
        "ZwDeviceIoControlFile",
        "NtLoadDriver",
        "ZwLoadDriver",
        "NtUnloadDriver",
        "ZwUnloadDriver",
    },
    "persistence": {
        "RegCreateKeyA",
        "RegCreateKeyW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueA",
        "RegSetValueW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegOpenKeyA",
        "RegOpenKeyW",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "CreateServiceA",
        "CreateServiceW",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "OpenServiceA",
        "OpenServiceW",
        "StartServiceA",
        "StartServiceW",
        "ChangeServiceConfigA",
        "ChangeServiceConfigW",
    },
    "filesystem": {
        "CreateFileA",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "DeleteFileA",
        "DeleteFileW",
        "MoveFileA",
        "MoveFileW",
        "MoveFileExA",
        "MoveFileExW",
        "CopyFileA",
        "CopyFileW",
        "SetFileAttributesA",
        "SetFileAttributesW",
        "FindFirstFileA",
        "FindFirstFileW",
        "FindNextFileA",
        "FindNextFileW",
    },
    "network": {
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "send",
        "sendto",
        "recv",
        "recvfrom",
        "WSAStartup",
        "WSASocketA",
        "WSASocketW",
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
    },
    "crypto": {
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptHashData",
        "CryptDeriveKey",
        "CryptGenKey",
        "CryptGenRandom",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptImportKey",
        "CryptExportKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptGenRandom",
        "BCryptGenerateSymmetricKey",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptHashData",
        "NCryptOpenStorageProvider",
        "NCryptOpenKey",
        "NCryptEncrypt",
        "NCryptDecrypt",
        "NCryptExportKey",
        "NCryptImportKey",
    },
}

CATEGORY_DESCRIPTIONS = {
    "process_handle_access": "Can open handles to other processes or threads.",
    "process_injection": "Can create remote execution, APC, hook, or mapped-section style execution paths.",
    "remote_memory_manipulation": "Can read, write, allocate, or protect memory in another process.",
    "local_memory_manipulation": "Can allocate, protect, or modify executable memory locally.",
    "native_loader_resolution": "Can dynamically load modules or resolve APIs at runtime.",
    "thread_context_control": "Can suspend, resume, or manipulate thread contexts.",
    "anti_debug": "Can support debugger, timing, exception, or environment checks.",
    "driver_kernel_surface": "Can communicate with device drivers or load/unload drivers.",
    "persistence": "Can modify registry/service persistence surfaces.",
    "filesystem": "Can modify or enumerate files.",
    "network": "Can communicate over sockets or HTTP APIs.",
    "crypto": "Can encrypt, decrypt, hash, generate randomness, or import/export keys.",
}


def classify_imports(imports) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for imported_dll in imports:
        for function in imported_dll.functions:
            normalized_function = normalize_api_name(function)
            for category, names in API_CATEGORIES.items():
                normalized_names = {normalize_api_name(name) for name in names}
                if normalized_function in normalized_names:
                    findings.append(
                        {
                            "dll": imported_dll.dll,
                            "function": function,
                            "category": category,
                            "severity": severity_for_category(category),
                            "description": CATEGORY_DESCRIPTIONS.get(category, "Sensitive API surface."),
                        }
                    )
    return deduplicate(findings)


def normalize_api_name(value: str) -> str:
    value = value.strip().lower()
    for prefix in ("__imp_", "_imp__", "_"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    return value


def severity_for_category(category: str) -> str:
    if category in {
        "process_injection",
        "remote_memory_manipulation",
        "thread_context_control",
        "driver_kernel_surface",
    }:
        return "high"
    if category in {
        "process_handle_access",
        "anti_debug",
        "persistence",
        "network",
        "crypto",
        "native_loader_resolution",
    }:
        return "medium"
    return "low"


def deduplicate(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for finding in findings:
        key = (finding["dll"].lower(), finding["function"].lower(), finding["category"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
