# Step 9.8 Crypto Analysis and Safe Transform Tools

This step adds crypto-aware static analysis and safe user-controlled transform tools.

## Included

- Crypto API inventory
  - Windows CryptoAPI / CNG
  - NCrypt
  - OpenSSL-style symbol names
  - common compression/encoding APIs

- Crypto constant detection
  - AES S-box fragments
  - SHA-256 initial constants / round constants
  - MD5 initial constants
  - ChaCha/Salsa marker strings
  - PEM / ASN.1 / certificate-like markers

- Encoded string candidate detection
  - Base64-like strings
  - hex blob strings
  - URL-encoded strings
  - PEM blocks
  - JWT-like strings

- High-entropy region scanning
  - Passive file window entropy scan
  - Offset/size/entropy reporting

- Safe transform CLI
  - Base64 decode
  - Hex decode
  - URL decode
  - XOR using a user-supplied key only

## Excluded

The project does not implement:

- key extraction from protected software
- brute-force cracking
- VMProtect decryption or unpacking
- license bypass
- automatic configuration decryption without user-supplied keys
- password/hash cracking
- exploit payload generation
- patch/crack generation

## Rationale

The crypto module is for defensive triage and authorized reverse engineering. It helps identify cryptographic usage and lets analysts apply known keys or simple encodings to their own data, without defeating software protections.
