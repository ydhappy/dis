from __future__ import annotations

from pathlib import Path
from typing import Any

import pefile


class CapstoneUnavailableError(RuntimeError):
    """Raised when capstone is not installed."""


class UnsupportedArchitectureError(RuntimeError):
    """Raised when disassembly architecture is unsupported."""


def disassemble_entry_point(
    target: str | Path,
    instruction_limit: int = 80,
    byte_limit: int = 512,
) -> list[dict[str, Any]]:
    """Disassemble a small static window at the PE entry point.

    This is a passive static view. It does not execute, modify, unpack, patch, or bypass the target.
    """
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    except ImportError as exc:  # pragma: no cover - depends on optional dependency
        raise CapstoneUnavailableError(
            "capstone is not installed. Install with: pip install -e .[disasm]"
        ) from exc

    path = Path(target)
    pe = pefile.PE(str(path), fast_load=False)
    try:
        machine = pe.FILE_HEADER.Machine
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_va = image_base + entry_rva
        entry_offset = pe.get_offset_from_rva(entry_rva)

        with path.open("rb") as file:
            file.seek(entry_offset)
            code = file.read(max(byte_limit, 1))

        if machine == 0x014C:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif machine == 0x8664:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        elif machine == 0xAA64:
            disassembler = Cs(CS_ARCH_ARM64, 0)
        else:
            raise UnsupportedArchitectureError(f"Unsupported architecture for disassembly: 0x{machine:04X}")

        disassembler.detail = False
        instructions: list[dict[str, Any]] = []
        for index, instruction in enumerate(disassembler.disasm(code, entry_va)):
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
        return instructions
    finally:
        pe.close()
