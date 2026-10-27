import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, wrpcap

from netsentry.analyzer import analyze_capture


class AnalyzerTests(unittest.TestCase):
    def make_capture(self, folder):
        path = Path(folder) / "synthetic.pcap"
        packets = [
            Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=50000, dport=443),
            Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=50000, dport=443),
            Ether() / IP(src="192.0.2.11", dst="198.51.100.30") / UDP(sport=53000, dport=5353),
        ]
        wrpcap(str(path), packets)
        return path

    def test_counts_packets_and_protocols(self):
        with tempfile.TemporaryDirectory() as folder:
            report = analyze_capture(self.make_capture(folder))
        self.assertEqual(report["summary"]["packet_count"], 3)
        self.assertEqual(report["summary"]["tcp_packets"], 2)
        self.assertEqual(report["summary"]["udp_packets"], 1)
        self.assertEqual(report["protocol_counts"]["TCP"], 2)

    def test_rejects_missing_capture(self):
        with self.assertRaises(FileNotFoundError):
            analyze_capture("does-not-exist.pcap")

    def test_rejects_invalid_top(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                analyze_capture(self.make_capture(folder), top_n=0)


if __name__ == "__main__":
    unittest.main()
