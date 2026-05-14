from __future__ import annotations

from typing import Any

BRANCH_PREFIXES = ("j", "loop")
CALL_MNEMONICS = {"call", "bl"}
RETURN_MNEMONICS = {"ret", "retf", "iret", "iretq", "retn"}
TERMINATOR_MNEMONICS = RETURN_MNEMONICS | {"jmp", "br"}


def build_flow_summary(disassembly: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a lightweight static flow summary from a disassembly window.

    This is a visualization/triage helper only. It does not deobfuscate or modify the target.
    """
    if not disassembly:
        return {
            "available": False,
            "instruction_count": 0,
            "branch_count": 0,
            "call_count": 0,
            "return_count": 0,
            "basic_blocks": [],
            "edges": [],
        }

    block_starts = {disassembly[0].get("address")}
    address_to_index = {item.get("address"): index for index, item in enumerate(disassembly)}

    for index, instruction in enumerate(disassembly):
        mnemonic = normalize_mnemonic(instruction)
        target = extract_hex_target(str(instruction.get("op_str", "")))
        if is_control_flow(mnemonic):
            if index + 1 < len(disassembly):
                block_starts.add(disassembly[index + 1].get("address"))
            if target in address_to_index:
                block_starts.add(target)

    ordered_starts = [item.get("address") for item in disassembly if item.get("address") in block_starts]
    basic_blocks: list[dict[str, Any]] = []
    for block_index, start in enumerate(ordered_starts):
        start_idx = address_to_index[start]
        next_start_idx = (
            address_to_index[ordered_starts[block_index + 1]]
            if block_index + 1 < len(ordered_starts)
            else len(disassembly)
        )
        instructions = disassembly[start_idx:next_start_idx]
        if not instructions:
            continue
        basic_blocks.append(
            {
                "id": f"B{block_index}",
                "start": instructions[0].get("address"),
                "end": instructions[-1].get("address"),
                "instruction_count": len(instructions),
                "terminator": normalize_mnemonic(instructions[-1]),
            }
        )

    edges = build_edges(disassembly, basic_blocks, address_to_index)
    branch_count = sum(1 for item in disassembly if is_branch(normalize_mnemonic(item)))
    call_count = sum(1 for item in disassembly if normalize_mnemonic(item) in CALL_MNEMONICS)
    return_count = sum(1 for item in disassembly if normalize_mnemonic(item) in RETURN_MNEMONICS)

    return {
        "available": True,
        "instruction_count": len(disassembly),
        "branch_count": branch_count,
        "call_count": call_count,
        "return_count": return_count,
        "basic_block_count": len(basic_blocks),
        "edge_count": len(edges),
        "basic_blocks": basic_blocks,
        "edges": edges,
    }


def build_edges(
    disassembly: list[dict[str, Any]],
    basic_blocks: list[dict[str, Any]],
    address_to_index: dict[Any, int],
) -> list[dict[str, str]]:
    start_to_block = {block["start"]: block["id"] for block in basic_blocks}
    address_to_block: dict[Any, str] = {}
    for block in basic_blocks:
        start_idx = address_to_index.get(block["start"])
        end_idx = address_to_index.get(block["end"])
        if start_idx is None or end_idx is None:
            continue
        for index in range(start_idx, end_idx + 1):
            address_to_block[disassembly[index].get("address")] = block["id"]

    edges: list[dict[str, str]] = []
    for index, instruction in enumerate(disassembly):
        mnemonic = normalize_mnemonic(instruction)
        source = address_to_block.get(instruction.get("address"))
        if not source:
            continue

        target = extract_hex_target(str(instruction.get("op_str", "")))
        if target in start_to_block:
            edges.append({"source": source, "target": start_to_block[target], "type": "branch"})

        if is_conditional_branch(mnemonic) and index + 1 < len(disassembly):
            fallthrough_address = disassembly[index + 1].get("address")
            target_block = address_to_block.get(fallthrough_address)
            if target_block:
                edges.append({"source": source, "target": target_block, "type": "fallthrough"})

    return dedupe_edges(edges)


def normalize_mnemonic(instruction: dict[str, Any]) -> str:
    return str(instruction.get("mnemonic", "")).lower().strip()


def is_branch(mnemonic: str) -> bool:
    return mnemonic.startswith(BRANCH_PREFIXES) or mnemonic in {"jmp", "br", "cbz", "cbnz", "tbz", "tbnz"}


def is_conditional_branch(mnemonic: str) -> bool:
    return is_branch(mnemonic) and mnemonic not in {"jmp", "br"}


def is_control_flow(mnemonic: str) -> bool:
    return is_branch(mnemonic) or mnemonic in CALL_MNEMONICS or mnemonic in RETURN_MNEMONICS


def extract_hex_target(operand_text: str) -> str | None:
    for token in operand_text.replace(",", " ").split():
        cleaned = token.strip("[]()")
        if cleaned.lower().startswith("0x"):
            try:
                return f"0x{int(cleaned, 16):X}"
            except ValueError:
                return None
    return None


def dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for edge in edges:
        key = (edge["source"], edge["target"], edge["type"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique
