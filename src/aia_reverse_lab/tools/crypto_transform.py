from __future__ import annotations

import base64
import binascii
from pathlib import Path
from urllib.parse import unquote_to_bytes


class TransformError(ValueError):
    """Raised when a safe transform cannot be performed."""


def read_input_bytes(value: str | None = None, input_file: str | Path | None = None) -> bytes:
    if input_file:
        return Path(input_file).read_bytes()
    if value is None:
        raise TransformError("No input value or input file was provided.")
    return value.encode("utf-8")


def write_output_bytes(data: bytes, output_file: str | Path | None = None) -> str:
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        Path(output_file).write_bytes(data)
        return str(output_file)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex(" ")


def transform_bytes(
    *,
    operation: str,
    data: bytes,
    key: str | None = None,
) -> bytes:
    operation = operation.lower().strip()
    if operation == "base64-decode":
        return base64.b64decode(data, validate=True)
    if operation == "base64-encode":
        return base64.b64encode(data)
    if operation == "hex-decode":
        cleaned = data.decode("utf-8", errors="strict").strip().replace(" ", "").replace("0x", "")
        return binascii.unhexlify(cleaned)
    if operation == "hex-encode":
        return binascii.hexlify(data)
    if operation == "url-decode":
        return unquote_to_bytes(data.decode("utf-8", errors="strict"))
    if operation == "xor":
        if not key:
            raise TransformError("XOR requires a user-supplied --transform-key value.")
        key_bytes = parse_key(key)
        if not key_bytes:
            raise TransformError("XOR key must not be empty.")
        return bytes(byte ^ key_bytes[index % len(key_bytes)] for index, byte in enumerate(data))
    raise TransformError(
        "Unsupported transform operation. Supported: base64-decode, base64-encode, "
        "hex-decode, hex-encode, url-decode, xor."
    )


def parse_key(key: str) -> bytes:
    key = key.strip()
    if key.startswith("hex:"):
        return binascii.unhexlify(key[4:].replace(" ", ""))
    if key.startswith("utf8:"):
        return key[5:].encode("utf-8")
    return key.encode("utf-8")
