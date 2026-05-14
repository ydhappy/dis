# Step 9.9 Safe Viewer Tools Scope

This step adds tools that let analysts inspect values directly before report generation.

## Included

- Binary dump viewer
  - Offset/length based hexdump
  - ASCII preview
  - Entropy of viewed range
  - JSON output support

- Offline memory dump analyzer
  - Reads an existing dump file supplied by the user
  - Detects printable strings
  - Finds PE/MZ signatures
  - Finds high-entropy regions
  - Does not attach to live processes
  - Does not dump another process memory

- Offline packet/PCAP analyzer
  - Reads an existing .pcap file supplied by the user
  - Parses global header, packet timestamps, Ethernet, IPv4, TCP, UDP, ICMP basics
  - Shows endpoints, ports, protocol, payload size, and payload preview
  - Does not sniff live network traffic

- Opcode/range viewer
  - Disassembles a user-selected file range or raw byte string
  - Requires optional Capstone dependency
  - Does not patch or modify the target

- Safe transform tools
  - Base64, hex, URL decode/encode
  - XOR with a user-supplied key only

## Excluded

The project does not implement:

- live process memory dumping
- credential extraction
- key extraction from protected software
- live packet sniffing
- network interception
- protection bypass
- VMProtect unpacking/devirtualization
- crack/patch generation

## Rationale

The goal is to inspect data safely from files the analyst already has: PE files, memory dumps, packet captures, and byte ranges. These features help defensive analysis without adding live collection or bypass capabilities.
