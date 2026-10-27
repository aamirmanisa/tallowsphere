#!/usr/bin/env python3
"""Generate the classic-PCAP fixtures for src/stdlib/intel_traffic.rs.

Deterministic: no clock, no randomness, no network. Every byte is a function of
the packet list below, so the committed .pcap files are reproducible with

    python3 tests/fixtures/intel_traffic/gen_pcap.py

from the repository root. Two files are written from the *same* packet list:

  sample-le-usec.pcap  magic d4 c3 b2 a1 — little-endian writer, microsecond
                       timestamps (the common case)
  sample-be-usec.pcap  magic a1 b2 c3 d4 — big-endian writer, microsecond
                       timestamps (proves the magic is read, not assumed)

The packets are chosen so that one file exercises all three of N28's evidence
classes and N30's flow merging:

  1. 10.0.0.5 -> 93.184.216.34:443  TLS ClientHello   (payload evidence -> https)
  2. 93.184.216.34:443 -> 10.0.0.5  TLS app data      (same flow, bytes_in)
  3. 10.0.0.5 -> 198.51.100.9:80    "GET / HTTP/1.1"  (payload evidence -> http)
  4. 10.0.0.5 -> 203.0.113.53:53    DNS query         (payload evidence -> dns)
  5. 203.0.113.53:53 -> 10.0.0.5    DNS response      (same flow, bytes_in)
  6. 10.0.0.5 -> 192.0.2.7:9999     SSH banner        (signature on an odd port)
"""

import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4(dotted: str) -> bytes:
    return bytes(int(part) for part in dotted.split("."))


ETH = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total, ident, 0x4000, 64, proto, 0,
        ip4(src), ip4(dst),
    )
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, sport, dst, dport, payload, ident, seq=1000, ack=1, flags=0x18):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    return ETH + b"\x08\x00" + ipv4(src, dst, 6, hdr + payload, ident)


def udp(src, sport, dst, dport, payload, ident):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ETH + b"\x08\x00" + ipv4(src, dst, 17, hdr + payload, ident)


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(qid, name):
    return (
        struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", 1, 1)
    )


def dns_response(qid, name, answer_ip):
    return (
        struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + ip4(answer_ip)
    )


# A ClientHello: record type 0x16 (handshake), version 0x0301, handshake type
# 0x01 at index 5 — the bytes the attribution table keys on.
TLS_CH = (
    b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03"
    + bytes(range(32))
    + b"\x00\x00\x04\xc0\x2f\xc0\x30\x01\x00\x00\x02\x00\x2b"
)

PACKETS = [
    (1000, 0, tcp("10.0.0.5", 51515, "93.184.216.34", 443, TLS_CH, 1, flags=0x02)),
    (1000, 100000, tcp("93.184.216.34", 443, "10.0.0.5", 51515, b"\x17\x03\x03\x00\x04" + b"\xaa" * 60, 2)),
    (1001, 0, tcp("10.0.0.5", 51516, "198.51.100.9", 80,
                       b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", 3)),
    (1002, 0, udp("10.0.0.5", 51517, "203.0.113.53", 53, dns_query(0x1234, "example.test"), 4)),
    (1002, 50000, udp("203.0.113.53", 53, "10.0.0.5", 51517,
                       dns_response(0x1234, "example.test", "93.184.216.34"), 5)),
    (1003, 0, tcp("10.0.0.5", 51518, "192.0.2.7", 9999,
                       b"SSH-2.0-OpenSSH_9.6\r\n", 6)),
]


def render(le: bool) -> bytes:
    e = "<" if le else ">"
    magic = 0xA1B2C3D4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for sec, usec, frame in PACKETS:
        out += struct.pack(e + "IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def main() -> None:
    for name, le in (("sample-le-usec.pcap", True), ("sample-be-usec.pcap", False)):
        blob = render(le)
        path = HERE / name
        path.write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        print(f"{name}: {len(blob)} bytes, {len(PACKETS)} records, sha256 {digest}")


if __name__ == "__main__":
    main()
