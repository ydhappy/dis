from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Any

PCAP_MAGIC_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}

ETHERTYPE_IPV4 = 0x0800
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def analyze_pcap(path: str | Path, max_packets: int = 100, payload_preview: int = 64) -> dict[str, Any]:
    pcap_path = Path(path)
    data = pcap_path.read_bytes()
    if len(data) < 24:
        raise ValueError("Invalid PCAP: file is too small.")

    magic = data[:4]
    endian = PCAP_MAGIC_ENDIAN.get(magic)
    if not endian:
        raise ValueError("Unsupported or invalid PCAP magic.")

    version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
        f"{endian}HHIIII", data[4:24]
    )
    offset = 24
    packets: list[dict[str, Any]] = []

    while offset + 16 <= len(data) and len(packets) < max_packets:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        packet_data = data[offset : offset + incl_len]
        offset += incl_len
        packets.append(parse_packet(packet_data, ts_sec, ts_usec, incl_len, orig_len, payload_preview))

    return {
        "path": str(pcap_path),
        "size": len(data),
        "version": f"{version_major}.{version_minor}",
        "snaplen": snaplen,
        "network": network,
        "packet_count_returned": len(packets),
        "packets": packets,
        "note": "Offline PCAP analysis only. This tool does not sniff live network traffic.",
    }


def parse_packet(
    data: bytes,
    ts_sec: int,
    ts_usec: int,
    incl_len: int,
    orig_len: int,
    payload_preview: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "timestamp": f"{ts_sec}.{ts_usec:06d}",
        "included_length": incl_len,
        "original_length": orig_len,
        "layers": [],
    }
    if len(data) < 14:
        result["error"] = "short ethernet frame"
        return result

    dst_mac = format_mac(data[0:6])
    src_mac = format_mac(data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    result["layers"].append(
        {"name": "ethernet", "src": src_mac, "dst": dst_mac, "ethertype": f"0x{ethertype:04X}"}
    )

    if ethertype == ETHERTYPE_IPV4 and len(data) >= 34:
        parse_ipv4(data[14:], result, payload_preview)
    else:
        result["payload_preview_hex"] = data[14 : 14 + payload_preview].hex(" ")
    return result


def parse_ipv4(data: bytes, result: dict[str, Any], payload_preview: int) -> None:
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl or ihl < 20:
        result["error"] = "invalid ipv4 header"
        return
    total_length = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    result["layers"].append(
        {"name": "ipv4", "src": src_ip, "dst": dst_ip, "protocol": protocol, "total_length": total_length}
    )
    payload = data[ihl:total_length] if total_length <= len(data) else data[ihl:]
    if protocol == IPPROTO_TCP:
        parse_tcp(payload, result, payload_preview)
    elif protocol == IPPROTO_UDP:
        parse_udp(payload, result, payload_preview)
    elif protocol == IPPROTO_ICMP:
        result["layers"].append({"name": "icmp", "payload_length": len(payload)})
        result["payload_preview_hex"] = payload[:payload_preview].hex(" ")
    else:
        result["payload_preview_hex"] = payload[:payload_preview].hex(" ")


def parse_tcp(data: bytes, result: dict[str, Any], payload_preview: int) -> None:
    if len(data) < 20:
        result["error"] = "short tcp segment"
        return
    src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHIIH", data[:14])
    data_offset = ((offset_flags >> 12) & 0xF) * 4
    flags = offset_flags & 0x01FF
    payload = data[data_offset:] if data_offset <= len(data) else b""
    result["layers"].append(
        {
            "name": "tcp",
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": f"0x{flags:03X}",
            "payload_length": len(payload),
        }
    )
    result["payload_preview_hex"] = payload[:payload_preview].hex(" ")
    result["payload_preview_ascii"] = ascii_preview(payload[:payload_preview])


def parse_udp(data: bytes, result: dict[str, Any], payload_preview: int) -> None:
    if len(data) < 8:
        result["error"] = "short udp datagram"
        return
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    payload = data[8:length] if length <= len(data) else data[8:]
    result["layers"].append(
        {
            "name": "udp",
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "checksum": f"0x{checksum:04X}",
            "payload_length": len(payload),
        }
    )
    result["payload_preview_hex"] = payload[:payload_preview].hex(" ")
    result["payload_preview_ascii"] = ascii_preview(payload[:payload_preview])


def format_mac(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)
