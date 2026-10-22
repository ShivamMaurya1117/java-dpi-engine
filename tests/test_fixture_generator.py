"""Independent framing/checksum checks for the generated artifact (stdlib only)."""
import ipaddress
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FixtureGeneratorTest(unittest.TestCase):
    def test_regeneration_matches_committed_artifact(self):
        build = runpy.run_path(str(ROOT / "generate_test_pcap.py"))["capture"]
        self.assertEqual(build(), build())
        self.assertEqual((ROOT / "test_dpi.pcap").read_bytes(), build())

    def test_wire_lengths_addresses_timestamps_and_checksums(self):
        data = (ROOT / "test_dpi.pcap").read_bytes()
        self.assertEqual(struct.unpack_from("<IHHIIII", data),
                         (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        networks = tuple(ipaddress.ip_network(n) for n in
                         ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
        cursor, count, protocols, flows = 24, 0, [], set()
        while cursor < len(data):
            seconds, micros, captured, original = struct.unpack_from("<4I", data, cursor)
            self.assertEqual((seconds - 1704067200) * 1000000 + micros, count * 125000)
            self.assertEqual(captured, original)
            packet = data[cursor + 16:cursor + 16 + captured]
            self.assertEqual(len(packet), captured)
            self.assertEqual(packet[12:14], b"\x08\x00")
            ip = packet[14:]
            self.assertEqual(len(ip), struct.unpack_from("!H", ip, 2)[0])
            protocol = ip[9]
            protocols.append(protocol)
            for address in (ip[12:16], ip[16:20]):
                self.assertTrue(any(ipaddress.ip_address(address) in net for net in networks))
            transport = ip[20:]
            flows.add((ip[12:20], transport[:4], protocol))
            if protocol == 17:
                self.assertEqual(struct.unpack_from("!H", transport, 4)[0], len(transport))
            pseudo = ip[12:20] + struct.pack("!BBH", 0, protocol, len(transport))
            for checked in (ip[:20], pseudo + transport):
                checked += b"\0" if len(checked) % 2 else b""
                total = sum(struct.unpack(f"!{len(checked)//2}H", checked))
                while total > 65535:
                    total = (total & 65535) + (total >> 16)
                self.assertEqual(total, 65535)
            cursor += 16 + captured
            count += 1
        self.assertEqual(cursor, len(data))
        self.assertEqual((count, len(flows), protocols.count(6), protocols.count(17)), (12, 8, 8, 4))

    def test_check_mode_detects_changed_output_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.pcap"
            command = [sys.executable, str(ROOT / "generate_test_pcap.py"), "--output", str(output)]
            subprocess.run(command, check=True, capture_output=True)
            subprocess.run(command + ["--check"], check=True, capture_output=True)
            changed = output.read_bytes()[:-1]
            output.write_bytes(changed)
            result = subprocess.run(command + ["--check"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), changed)


if __name__ == "__main__":
    unittest.main()
