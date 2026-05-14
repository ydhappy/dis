# Step 9.10 Boundaries and Problem Location

This project does not implement capabilities that would directly bypass protections, crack licensing, dump live process memory, sniff live traffic, or unpack third-party protected software.

## Not implemented

- Live process memory dumping
- Credential/key extraction from another process
- Live packet sniffing/interception
- VMProtect unpacking/devirtualization
- Anti-debug bypass automation
- License check bypass or license emulator generation
- Patch/crack generation
- Loader/stub generation for defeating protection

## Implemented direction instead

The goal is to help an analyst find where a problem likely exists without bypassing protections.

AIA Reverse Lab uses these safe inputs:

- PE headers and section layout
- EntryPoint section mapping
- Section entropy and permissions
- TLS directory and callback metadata
- Import/export tables
- Static strings
- YARA matches
- Offline memory dumps supplied by the user
- Offline PCAP files supplied by the user
- User-selected opcode ranges
- Safe binary diff between two authorized files
- User-supplied transform keys only

## Problem location strategy

The analyzer points the user to likely investigation locations:

- EntryPoint section if high entropy, RWX, or VMProtect-like section names appear
- TLS callbacks if present
- Sparse/missing import table when packer/protector behavior is likely
- High-entropy file regions for encrypted/packed blobs
- Crypto API and crypto constant locations
- Encoded string candidates
- Changed ranges between authorized original/modified files
- Offline PCAP payload previews and endpoints
- Offline memory dump MZ/PE offsets and high-entropy regions

This keeps the tool useful for debugging and research while avoiding automation that defeats software protections or extracts secrets.
