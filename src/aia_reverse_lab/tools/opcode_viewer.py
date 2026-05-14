from __future__ import annotations

import binascii
from pathlib import Path
from typing import Any


class OpcodeViewerError(RuntimeError):
    """Raised when opcode viewing cannot be performed."""


def disassemble_bytes(
    *,
    data: bytes,
    architecture: str = "x64",
    base_address: int = 0,
    instruction_limit: int = 200,
) -> dict[str, Any]:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
    except ImportError as exc:  # pragma: no cover
        raise OpcodeViewerError("capstone is not installed. Install with: pip install -e .[disasm]") from exc

    architecture = architecture.lower().strip()
    if architecture in {"x86", "i386", "32"}:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    elif architecture in {"x64", "amd64", "64"}:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    elif architecture in {"arm64", "aarch64"}:
        disassembler = Cs(CS_ARCH_ARM64, 0)
    elif architecture in {"arm", "arm32"}:
        disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        raise OpcodeViewerError(f"Unsupported architecture: {architecture}")

    instructions: list[dict[str, Any]] = []
    for index, instruction in enumerate(disassembler.disasm(data, base_address)):
        if index >= instruction_limit:
            break
        instructions.append(
            {
                "address": f"0x{instruction.address:X}",
                "size": instruction.size,
                "bytes": instruction.bytes.hex(" "),
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
        )

    return {
        "architecture": architecture,
        "base_address": f"0x{base_address:X}",
        "byte_count": len(data),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


def disassemble_file_range(
    *,
    path: str | Path,
    offset: int = 0,
    length: int = 256,
    architecture: str = "x64",
    base_address: int | None = None,
    instruction_limit: int = 200,
) -> dict[str, Any]:
    file_path = Path(path)
    if offset < 0:
        raise OpcodeViewerError("offset must be >= 0")
    if length <= 0:
        raise OpcodeViewerError("length must be > 0")
    with file_path.open("rb") as file:
        file.seek(offset)
        data = file.read(length)
    result = disassemble_bytes(
        data=data,
        architecture=architecture,
        base_address=offset if base_address is None else base_address,
        instruction_limit=instruction_limit,
    )
    result["path"] = str(file_path)
    result["offset"] = f"0x{offset:X}"
    result["length_requested"] = length
    return result


def disassemble_hex_string(
    *,
    hex_string: str,
    architecture: str = "x64",
    base_address: int = 0,
    instruction_limit: int = 200,
) -> dict[str, Any]:
    cleaned = hex_string.replace(" ", "").replace("\n", "").replace("\t", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    try:
        data = binascii.unhexlify(cleaned)
    except binascii.Error as exc:
        raise OpcodeViewerError(f"Invalid hex string: {exc}") from exc
    return disassemble_bytes(
        data=data,
        architecture=architecture,
        base_address=base_address,
        instruction_limit=instruction_limit,
    )


def parse_integer(value: str | int | None, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value)
