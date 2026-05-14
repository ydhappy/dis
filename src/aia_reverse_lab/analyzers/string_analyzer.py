from __future__ import annotations

import re
from pathlib import Path

ASCII_PATTERN = re.compile(rb"[\x20-\x7E]{4,}")
UTF16LE_PATTERN = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")


SUSPICIOUS_STRING_KEYWORDS = {
    "url": ["http://", "https://", "ftp://"],
    "script": ["powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32"],
    "registry": ["hkey_current_user", "hkey_local_machine", "\\software\\microsoft\\windows"],
    "credential": ["password", "passwd", "token", "apikey", "secret"],
    "network": ["user-agent", "socket", "connect", "download", "upload"],
    "anti_analysis": ["debugger", "ollydbg", "x64dbg", "wireshark", "procmon", "ida"],
}


def classify_string(value: str) -> list[str]:
    lowered = value.lower()
    tags: list[str] = []
    for tag, needles in SUSPICIOUS_STRING_KEYWORDS.items():
        if any(needle in lowered for needle in needles):
            tags.append(tag)
    return tags


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
            }
        )
        if len(results) >= limit:
            return results

    return results
