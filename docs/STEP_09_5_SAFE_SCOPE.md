# Step 9.5 Safe Scope: Flow, Patch Diff, and Required Data Analysis

This step adds safe defensive-analysis features before Step 10 tests/CI.

## Included

- Anti-analysis / bypass indicator analysis
  - Detects imported APIs and strings associated with anti-debugging, anti-VM, timing checks, and analysis-tool awareness.
  - Does not bypass or disable those mechanisms.

- Patch / tamper diff analysis
  - Compares two authorized files and reports changed byte ranges, hashes, and offsets.
  - Does not generate patches, cracks, loaders, keygens, or modified executables.

- Static flow summary
  - Builds a lightweight control-flow summary from the EntryPoint disassembly window.
  - Intended for visualization and triage, not deobfuscation or protector removal.

- Required data analysis
  - Reports which analysis inputs are present or missing.
  - Helps users know whether PE metadata, strings, imports, YARA, disassembly, and reports are available.

## Excluded

The project does not implement:

- Commercial protector bypass
- VMProtect unpacking automation
- License check removal
- Crack patch generation
- Anti-debug bypass automation
- OEP reconstruction for protected third-party software
- IAT reconstruction for rebuilding protected executables
- Loader/stub generation for circumventing protections

## Rationale

AIA Reverse Lab is intended for authorized reverse engineering, malware triage, CTF/lab binaries, and defensive software analysis. Protected binaries may be inspected, scored, and reported, but the project must not provide automation that defeats protection mechanisms or facilitates unauthorized modification.
