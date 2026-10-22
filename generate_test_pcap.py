#!/usr/bin/env python3
"""Build the independently designed portfolio fixture; never sends network traffic.

Python 3 standard library only. All addresses use TEST-NET blocks, all names
are beneath example.com/org/net, and every byte is deterministic. See
 docs/FIXTURE.md for the scenario contract and provenance boundary.
"""
from argparse import ArgumentParser
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
import struct


def checksum(octets: bytes) -> int:
    padded = octets + (b"\0" if len(octets) % 2 else b"")
    total = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def vector(octets: bytes, width: int = 2) -> bytes:
    return len(octets).to_bytes(width, "big") + octets


def client_hello(host: str) -> bytes:
    # TLS 1.2-shaped ClientHello, one cipher and one server-name extension.
    server_name = b"\0" + vector(host.encode("ascii"))
    extension = b"\0\0" + vector(vector(server_name))
    body = (b"\x03\x03" + bytes(range(32)) + b"\0"
            + vector(b"\x00\x2f") + b"\x01\0" + vector(extension))
    handshake = b"\x01" + vector(body, 3)
    return b"\x16\x03\x03" + vector(handshake)


def question(host: str, identifier: int) -> bytes:
    labels = b"".join(vector(label.encode("ascii"), 1) for label in host.split("."))
    return struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + labels + b"\0\0\x01\0\x01"


def frame(source: str, destination: str, sport: int, dport: int,
          protocol: int, payload: bytes, ordinal: int, flags: int = 0x18) -> bytes:
    addresses = IPv4Address(source).packed + IPv4Address(destination).packed
    if protocol == 6:
        segment = struct.pack("!HHIIBBHHH", sport, dport, 1000 + ordinal * 100,
                              0, 0x50, flags, 4096, 0, 0) + payload
        checksum_offset = 16
    else:
        segment = struct.pack("!4H", sport, dport, 8 + len(payload), 0) + payload
        checksum_offset = 6
    pseudo = addresses + struct.pack("!BBH", 0, protocol, len(segment))
    transport_sum = checksum(pseudo + segment)
    if protocol == 17 and transport_sum == 0:
        transport_sum = 65535
    segment = (segment[:checksum_offset] + struct.pack("!H", transport_sum)
               + segment[checksum_offset + 2:])
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), ordinal,
                         0x4000, 64, protocol, 0) + addresses
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + header + segment


def capture() -> bytes:
    # Four directional TCP flows, then four independent UDP flows. Ordering
    # intentionally exposes an allowed SYN before a later domain-based block.
    scenarios = [
        ("192.0.2.10", "198.51.100.10", 41000, 80, 6, b"", 0x02),
        ("192.0.2.10", "198.51.100.10", 41000, 80, 6,
         b"GET /status HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n", 0x18),
        ("192.0.2.11", "198.51.100.11", 41001, 80, 6,
         b"HEAD /report HTTP/1.1\r\nHost: denied.example.org\r\n\r\n", 0x18),
        ("192.0.2.11", "198.51.100.11", 41001, 80, 6, b"", 0x10),
        ("192.0.2.12", "198.51.100.12", 41002, 443, 6, client_hello("api.example.net"), 0x18),
        ("192.0.2.12", "198.51.100.12", 41002, 443, 6, b"", 0x10),
        ("192.0.2.13", "198.51.100.13", 41003, 443, 6, b"", 0x02),
        ("192.0.2.13", "198.51.100.13", 41003, 443, 6, client_hello("secure.example.org"), 0x18),
        ("192.0.2.20", "203.0.113.53", 42000, 53, 17, question("dns.example.com", 10), 0),
        ("192.0.2.21", "203.0.113.53", 42001, 53, 17, question("query.example.net", 11), 0),
        ("203.0.113.99", "198.51.100.30", 43000, 9000, 17, b"blocked-datagram", 0),
        ("192.0.2.30", "198.51.100.31", 43001, 9001, 17, b"allowed-datagram", 0),
    ]
    result = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, scenario in enumerate(scenarios):
        source, destination, sport, dport, protocol, payload, flags = scenario
        packet = frame(source, destination, sport, dport, protocol, payload, index, flags)
        # Fixed epoch, 125 ms increments: no clock, randomness, DNS or network I/O.
        seconds, micros = divmod(index * 125000, 1000000)
        result.extend(struct.pack("<4I", 1704067200 + seconds, micros, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().with_name("test_dpi.pcap"))
    parser.add_argument("--check", action="store_true", help="compare expected bytes without writing")
    args = parser.parse_args()
    expected = capture()
    if args.check:
        if args.output.read_bytes() != expected:
            raise SystemExit("Fixture differs from deterministic generator output")
    else:
        args.output.write_bytes(expected)
    print(f"{'Verified' if args.check else 'Wrote'} {len(expected)} bytes; SHA-256 {sha256(expected).hexdigest()}")


if __name__ == "__main__":
    main()
