from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

CRYPTO_API_CATEGORIES = {
    "windows_cryptoapi": {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptGenKey", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt",
        "CryptImportKey", "CryptExportKey", "CryptDestroyKey", "CryptDestroyHash",
    },
    "windows_cng": {
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider", "BCryptGenRandom",
        "BCryptGenerateSymmetricKey", "BCryptEncrypt", "BCryptDecrypt", "BCryptHashData",
        "BCryptCreateHash", "BCryptFinishHash", "BCryptImportKey", "BCryptExportKey",
    },
    "windows_ncrypt": {
        "NCryptOpenStorageProvider", "NCryptOpenKey", "NCryptCreatePersistedKey", "NCryptEncrypt",
        "NCryptDecrypt", "NCryptSignHash", "NCryptVerifySignature", "NCryptExportKey", "NCryptImportKey",
    },
    "openssl_like": {
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
        "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex", "EVP_DigestInit_ex",
        "RSA_public_encrypt", "RSA_private_decrypt", "SHA256_Init", "SHA256_Update", "SHA256_Final",
    },
    "compression_encoding": {
        "RtlCompressBuffer", "RtlDecompressBuffer", "LZNT1", "RtlGetCompressionWorkSpaceSize",
    },
}

CRYPTO_MARKERS = {
    "aes_sbox_fragment": bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    "sha256_initial_constants": bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a"),
    "md5_initial_constants_le": bytes.fromhex("0123456789abcdeffedcba9876543210"),
    "chacha_sigma": b"expand 32-byte k",
    "salsa_sigma": b"expand 32-byte k",
    "pem_private_key": b"-----BEGIN PRIVATE KEY-----",
    "pem_rsa_private_key": b"-----BEGIN RSA PRIVATE KEY-----",
    "pem_certificate": b"-----BEGIN CERTIFICATE-----",
}

BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{16,}$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
URL_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


def analyze_crypto_features(path: str | Path, imports, strings: list[dict[str, Any]]) -> dict[str, Any]:
    data = Path(path).read_bytes()
    api_hits = detect_crypto_apis(imports)
    constant_hits = detect_crypto_constants(data)
    encoded_candidates = detect_encoded_candidates(strings)
    high_entropy_regions = scan_high_entropy_regions(data)

    return {
        "crypto_api_count": len(api_hits),
        "crypto_apis": api_hits,
        "constant_count": len(constant_hits),
        "constants": constant_hits,
        "encoded_candidate_count": len(encoded_candidates),
        "encoded_candidates": encoded_candidates[:200],
        "high_entropy_region_count": len(high_entropy_regions),
        "high_entropy_regions": high_entropy_regions[:200],
        "summary": build_summary(api_hits, constant_hits, encoded_candidates, high_entropy_regions),
    }


def detect_crypto_apis(imports) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for imported_dll in imports:
        for function in imported_dll.functions:
            for category, names in CRYPTO_API_CATEGORIES.items():
                if function in names:
                    hits.append({"category": category, "dll": imported_dll.dll, "function": function})
    return hits


def detect_crypto_constants(data: bytes) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lowered = data.lower()
    for name, marker in CRYPTO_MARKERS.items():
        marker_l = marker.lower()
        offset = lowered.find(marker_l)
        while offset != -1:
            hits.append({"name": name, "offset": f"0x{offset:X}", "length": len(marker)})
            offset = lowered.find(marker_l, offset + 1)
            if len(hits) >= 500:
                return hits
    return hits


def detect_encoded_candidates(strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in strings:
        value = str(item.get("value", "")).strip()
        if len(value) < 8:
            continue
        kind = classify_encoded_string(value)
        if not kind:
            continue
        candidates.append(
            {
                "kind": kind,
                "offset": item.get("offset", "unknown"),
                "length": len(value),
                "preview": value[:120],
            }
        )
    return candidates


def classify_encoded_string(value: str) -> str | None:
    if value.startswith("-----BEGIN ") and "-----END " in value:
        return "pem"
    if JWT_RE.match(value):
        return "jwt_like"
    if URL_ENCODED_RE.search(value) and len(value) >= 12:
        return "url_encoded"
    if HEX_RE.match(value) and len(value.replace("0x", "")) % 2 == 0:
        return "hex_blob"
    if len(value) % 4 == 0 and BASE64_RE.match(value):
        return "base64_like"
    return None


def scan_high_entropy_regions(data: bytes, window_size: int = 1024, threshold: float = 7.4) -> list[dict[str, Any]]:
    if len(data) < window_size:
        entropy = calculate_entropy(data)
        return [{"offset": "0x0", "size": len(data), "entropy": entropy}] if entropy >= threshold else []

    regions: list[dict[str, Any]] = []
    step = window_size
    for offset in range(0, len(data), step):
        chunk = data[offset : offset + window_size]
        if len(chunk) < 256:
            continue
        entropy = calculate_entropy(chunk)
        if entropy >= threshold:
            regions.append({"offset": f"0x{offset:X}", "size": len(chunk), "entropy": entropy})
        if len(regions) >= 500:
            break
    return merge_adjacent_regions(regions, window_size)


def merge_adjacent_regions(regions: list[dict[str, Any]], window_size: int) -> list[dict[str, Any]]:
    if not regions:
        return []
    merged: list[dict[str, Any]] = []
    current = dict(regions[0])
    entropies = [float(current["entropy"])]
    for region in regions[1:]:
        current_end = int(str(current["offset"]), 16) + int(current["size"])
        region_offset = int(str(region["offset"]), 16)
        if region_offset <= current_end:
            current["size"] = region_offset + int(region["size"]) - int(str(current["offset"]), 16)
            entropies.append(float(region["entropy"]))
            current["entropy"] = round(sum(entropies) / len(entropies), 4)
        else:
            merged.append(current)
            current = dict(region)
            entropies = [float(current["entropy"])]
    merged.append(current)
    return merged


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def build_summary(api_hits, constant_hits, encoded_candidates, high_entropy_regions) -> dict[str, Any]:
    return {
        "uses_crypto_api": bool(api_hits),
        "has_crypto_constants": bool(constant_hits),
        "has_encoded_candidates": bool(encoded_candidates),
        "has_high_entropy_regions": bool(high_entropy_regions),
        "note": "Static crypto indicators only. No keys are extracted and no protection is bypassed.",
    }
