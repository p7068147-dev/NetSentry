"""Offline network-capture summaries and simple heuristic alerts.

This module reads saved capture files only. It does not sniff live interfaces,
send packets, scan hosts, or attempt to exploit network services.
"""
from collections import Counter
from pathlib import Path
from typing import Any
import json

from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, rdpcap


WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-server", 68: "DHCP-client", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3389: "RDP",
}


def _ip_pair(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return None, None


def analyze_capture(path: str | Path, top_n: int = 10,
                    connection_threshold: int = 100) -> dict[str, Any]:
    """Analyze a saved PCAP/PCAPNG and return a JSON-serializable report."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")
    if top_n < 1:
        raise ValueError("top_n must be at least 1")
    if connection_threshold < 1:
        raise ValueError("connection_threshold must be at least 1")

    packets = rdpcap(str(path))
    protocol_counts = Counter()
    source_counts = Counter()
    destination_counts = Counter()
    destination_ports = Counter()
    source_dest_pairs = Counter()
    packet_bytes = 0
    tcp_packets = udp_packets = icmp_packets = dns_packets = 0

    for packet in packets:
        packet_bytes += len(packet)
        src, dst = _ip_pair(packet)
        if src:
            source_counts[src] += 1
            destination_counts[dst] += 1
            source_dest_pairs[(src, dst)] += 1
        if TCP in packet:
            protocol_counts["TCP"] += 1
            tcp_packets += 1
            destination_ports[int(packet[TCP].dport)] += 1
        elif UDP in packet:
            protocol_counts["UDP"] += 1
            udp_packets += 1
            destination_ports[int(packet[UDP].dport)] += 1
        elif ICMP in packet:
            protocol_counts["ICMP"] += 1
            icmp_packets += 1
        elif DNS in packet:
            protocol_counts["DNS"] += 1
            dns_packets += 1
        elif src:
            protocol_counts["IP-other"] += 1
        else:
            protocol_counts["non-IP"] += 1

        if DNS in packet:
            dns_packets += 1

    alerts = []
    # These are triage heuristics, not proof of malicious activity.
    for (src, dst), count in source_dest_pairs.most_common():
        if count >= connection_threshold:
            alerts.append({
                "severity": "low",
                "type": "repeated_source_destination_pair",
                "source": src,
                "destination": dst,
                "packet_count": count,
                "message": (
                    f"{src} and {dst} exchanged {count} captured packets; "
                    "review expected application behavior and capture duration."
                ),
            })

    unusual_ports = []
    for port, count in destination_ports.most_common():
        if port not in WELL_KNOWN_PORTS and count >= 3:
            unusual_ports.append({
                "port": port,
                "packet_count": count,
                "message": "Repeated traffic to a port not in this tool's small common-port list.",
            })

    if unusual_ports:
        alerts.append({
            "severity": "info",
            "type": "repeated_unlisted_destination_ports",
            "items": unusual_ports[:top_n],
            "message": "Unlisted ports are not inherently suspicious; investigate in context.",
        })

    return {
        "tool": "NetSentry",
        "version": "1.0.0",
        "capture_file": path.name,
        "summary": {
            "packet_count": len(packets),
            "captured_bytes": packet_bytes,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "dns_packet_count": dns_packets,
        },
        "protocol_counts": dict(protocol_counts.most_common()),
        "top_sources": [
            {"ip": ip, "packets": count}
            for ip, count in source_counts.most_common(top_n)
        ],
        "top_destinations": [
            {"ip": ip, "packets": count}
            for ip, count in destination_counts.most_common(top_n)
        ],
        "top_destination_ports": [
            {
                "port": port,
                "label": WELL_KNOWN_PORTS.get(port, "unlisted"),
                "packets": count,
            }
            for port, count in destination_ports.most_common(top_n)
        ],
        "alerts": alerts,
        "limitations": [
            "Heuristics may produce false positives and false negatives.",
            "Encrypted payloads are not decrypted or inspected.",
            "A port absent from the common-port list is not evidence of an attack.",
            "The report describes this capture only, not the whole network.",
        ],
    }


def write_json_report(report: dict[str, Any], output_path: str | Path) -> None:
    """Write report JSON to the requested path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
