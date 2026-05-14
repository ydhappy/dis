# Step 9.6 VMProtect Profile Analysis

This step adds VMProtect-aware static profiling for authorized research and defensive triage.

## Included

- VMProtect section marker detection
- VMProtect string/metadata marker detection
- EntryPoint section analysis
- High entropy section correlation
- Sparse import table analysis
- Overlay correlation
- Anti-analysis indicator correlation
- EntryPoint disassembly heuristic analysis
- VM-like dispatcher indicator tagging
- Confidence scoring and evidence list
- Safe analyst notes and next-step checklist

## Excluded

The project does not implement:

- VMProtect unpacking
- VMProtect virtualization devirtualization
- OEP recovery automation
- IAT reconstruction for rebuilding protected programs
- License check removal
- Anti-debug bypass automation
- Patch generation
- Loader/stub generation
- Key extraction

## Intended use

This module helps analysts decide whether a binary appears protected by VMProtect and which static signals support that conclusion. It is designed for reporting, triage, and comparing authorized binaries, not defeating software protection.
