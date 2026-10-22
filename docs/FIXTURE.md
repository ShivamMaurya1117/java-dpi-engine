# Deterministic synthetic PCAP fixture

[Overview](../README.md) · [API examples](API.md) · [Provenance](../PROVENANCE.md)

The synthetic fixture contains reserved addresses and example domains for repeatable packet-local inspection tests. It is generated entirely with the Python standard library. See [PROVENANCE.md](../PROVENANCE.md) for attribution and the scope of fixture authorship.

## Generation and wire format

Python 3, standard library only; no network traffic, DNS lookup, randomness or wall-clock dependency. From the repository root in PowerShell:

```powershell
py -3 generate_test_pcap.py
py -3 generate_test_pcap.py --check
py -3 -m unittest discover -s tests -v
```

Generation overwrites the root capture with deterministic bytes. `--check` compares without writing. `--output PATH` selects another destination; its parent directory must exist. On other platforms use `python3` instead of `py -3`. Python is optional for Java builds and Docker: the checked-in capture is used directly.

The 1,173-byte capture is little-endian classic PCAP 2.4, Ethernet link type 1, microsecond resolution, snapshot length 65,535. It contains 12 records with equal captured/original lengths. Record timestamps begin at 2024-01-01T00:00:00Z and increase by exactly 125 ms. Ethernet addresses are fixed locally administered addresses. IPv4 addresses come only from TEST-NET-1/2/3 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Every hostname is beneath example.com, example.org or example.net. IPv4 and TCP/UDP checksums are populated and independently checked by the Python tests.

These are packet-local inspection samples, not complete TCP/TLS sessions. SYN/ACK and payload observations are deliberately selected for flow-state behavior; the file is not intended for replay or endpoint interoperability testing.

SHA-256:

```text
DE6C52A35BCCE9326552AF74AEAFE1A7E2072117318B88873F6F350F4258CAEE
```

## Scenario contract

Record numbers below are zero-based. Each row represents one directional five-tuple.

| Records | Source → destination / ports | Contents | Final flow category | Example-rule outcome |
| --- | --- | --- | --- | --- |
| 0–1 | 192.0.2.10 → 198.51.100.10, 41000 → 80 | SYN, HTTP GET Host allowed.example.com | HTTP | Both allowed |
| 2–3 | 192.0.2.11 → 198.51.100.11, 41001 → 80 | HTTP HEAD Host denied.example.org, ACK | HTTP | Both domain-blocked; second uses sticky decision |
| 4–5 | 192.0.2.12 → 198.51.100.12, 41002 → 443 | TLS ClientHello SNI api.example.net, ACK | HTTPS | Both allowed |
| 6–7 | 192.0.2.13 → 198.51.100.13, 41003 → 443 | SYN, TLS ClientHello SNI secure.example.org | HTTPS | SYN allowed; subsequent SNI packet domain-blocked |
| 8 | 192.0.2.20 → 203.0.113.53, 42000 → 53 | UDP DNS question dns.example.com | DNS | Application-blocked |
| 9 | 192.0.2.21 → 203.0.113.53, 42001 → 53 | UDP DNS question query.example.net | DNS | Application-blocked |
| 10 | 203.0.113.99 → 198.51.100.30, 43000 → 9000 | Opaque UDP datagram | UNKNOWN | IPv4-blocked |
| 11 | 192.0.2.30 → 198.51.100.31, 43001 → 9001 | Opaque UDP datagram | UNKNOWN | Allowed |

Example rules are application `DNS`, domain `example.org`, IPv4 `203.0.113.99`. They exercise application, hostname and endpoint filtering without brand mappings. All 12 records parse: 8 TCP, 4 UDP, 8 flows. Final flow distribution is HTTP=2, HTTPS=2, DNS=2, UNKNOWN=2.

With those rules: 6 allowed, 6 blocked, 5 blocked flows; reasons APPLICATION DNS=2, DOMAIN example.org=3, IPV4 203.0.113.99=1. The filtered capture contains original records 0, 1, 4, 5, 6 and 11 in that order and is 575 bytes. The SYN at record 6 stays allowed because filtering is not retroactive. Without rules all records remain byte-for-byte identical to input.

The unchanged legacy CLI `--demo-rules` uses YOUTUBE/facebook.com/192.168.1.50 and does not match this fixture. Current examples use explicit flags instead. Specific brand classification continues to be covered by the existing classifier unit tests, not by this reserved-domain capture.

## Verification

On 2026-10-22, `mvn clean verify` passed **423 tests** (344 core + 79 API), and all **3 Python generator tests** passed. The current Docker Linux engine was unavailable, so container verification is pending.

Core/API tests verify no-rule byte equality, rule decisions and counts, retained-record ordering, and sequential/parallel equality with 2, 4 and 8 workers. The Docker verification script additionally compares 1/4/8-worker output when run against a server.

Python tests independently check deterministic regeneration, PCAP framing, timestamps, reserved addresses, protocol/flow counts, IP/transport checksums and read-only `--check` failure against altered bytes. See the [verification guide](../dpi-engine-api/VERIFICATION.md) for commands.
