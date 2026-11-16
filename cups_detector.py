#!/usr/bin/env python3
"""
cups_detector.py — Scapy-based detection tool for suspicious CUPS activity.

Detections implemented:
1. Unauthorized printer advertisements (UDP source IP not in allowlist).
2. Suspicious IPP connections (TCP 631 connections not in allowlist, or using Add-Modify-Printer).
3. Flood/abnormal discovery messages (too many UDP packets in a short time).
4. Malformed packets (bad UDP state field, unexpected URI scheme, or bad IPP version).
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, UDP, TCP, Raw, sniff, PcapReader


CUPS_PORT = 631
VALID_SCHEMES = ("ipp://", "ipps://", "http://", "https://")
# IPP Operation IDs (0x4001 = Add/Modify printer)
IPP_ADD_MODIFY_PRINTER = 0x4001

class CupsDetector:
    def __init__(self, allowlist, rate_threshold, window, max_size):
        self.allowlist = set(allowlist)
        self.rate_threshold = rate_threshold
        self.window = window
        self.max_size = max_size
        self.alerts = []
        self.stats = defaultdict(int)
        self.source_times = defaultdict(list)

    def add_alert(self, severity, category, src, dst, proto, detail):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "detail": detail
        }
        self.alerts.append(alert)
        self.stats[category] += 1
        print(f"[{severity.upper()}] {category}: {src} -> {dst} [{proto}] | {detail}")

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = len(pkt)

        # 1. Process UDP (Printer Discovery)
        if pkt.haslayer(UDP) and (pkt[UDP].sport == CUPS_PORT or pkt[UDP].dport == CUPS_PORT):
            self.process_udp(pkt, src, dst, pkt_len)

        # 2. Process TCP (IPP Connections)
        elif pkt.haslayer(TCP) and (pkt[TCP].sport == CUPS_PORT or pkt[TCP].dport == CUPS_PORT):
            self.process_tcp(pkt, src, dst, pkt_len)

    def process_udp(self, pkt, src, dst, pkt_len):
        self.stats["udp_packets_seen"] += 1

        # Check size
        if pkt_len > self.max_size:
            self.add_alert("medium", "oversized_packet", src, dst, "UDP", f"Packet length {pkt_len} exceeds max {self.max_size}")

        # Check rate limit (flood detection)
        now = time.time()
        self.source_times[src].append(now)
        self.source_times[src] = [t for t in self.source_times[src] if now - t <= self.window]
        if len(self.source_times[src]) > self.rate_threshold:
            self.add_alert("high", "discovery_flood", src, dst, "UDP", f"{len(self.source_times[src])} UDP packets in {self.window}s")

        # Check payload (Browse protocol)
        if not pkt.haslayer(Raw):
            return
        try:
            payload = pkt[Raw].load.decode('utf-8').strip()
        except UnicodeDecodeError:
            self.add_alert("medium", "malformed_packet", src, dst, "UDP", "Non-UTF8 payload")
            return

        parts = payload.split()
        if len(parts) < 3:
            return  # Not a browse line

        state_field, uri = parts[1], parts[2]

        # Check state field (should be integer)
        if not state_field.isdigit():
            self.add_alert("medium", "malformed_state", src, dst, "UDP", f"Invalid state field '{state_field}'")
            
        # Check URI scheme
        if not uri.lower().startswith(VALID_SCHEMES):
            self.add_alert("medium", "malformed_uri_scheme", src, dst, "UDP", f"Unexpected URI scheme in '{uri}'")

        # Check authorization
        if self.allowlist and src not in self.allowlist:
            self.add_alert("high", "unauthorized_advertisement", src, dst, "UDP", f"Printer advertised by unauthorized host: {uri}")

    def process_tcp(self, pkt, src, dst, pkt_len):
        self.stats["tcp_packets_seen"] += 1

        # Check IPP payload
        if not pkt.haslayer(Raw):
            return
        
        payload = bytes(pkt[Raw].load)
        
        # IPP header is 8 bytes
        if len(payload) < 8:
            self.add_alert("medium", "malformed_ipp", src, dst, "TCP", "IPP payload too short (less than 8 bytes)")
            return

        # Parse IPP header
        version = (payload[0], payload[1])
        op_id = int.from_bytes(payload[2:4], "big")

        # Check IPP version (should be 1.0, 1.1, or 2.0)
        if version not in [(1, 0), (1, 1), (2, 0)]:
            self.add_alert("medium", "malformed_ipp_version", src, dst, "TCP", f"Unexpected IPP version {version}")

        # Check for suspicious operations
        if op_id == IPP_ADD_MODIFY_PRINTER:
            self.add_alert("high", "suspicious_ipp_operation", src, dst, "TCP", f"IPP Add-Modify-Printer operation (0x4001) detected")

        # Check authorization 
        if self.allowlist and src not in self.allowlist:
            self.add_alert("medium", "unauthorized_ipp_connection", src, dst, "TCP", f"IPP connection from unauthorized host (op: 0x{op_id:04x})")

    def run(self, iface=None, pcap_file=None):
        if pcap_file:
            print(f"[*] Analyzing {pcap_file}...")
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    self.process_packet(pkt)
        else:
            print(f"[*] Live capture on {iface or 'default'}...")
            # Capture both UDP and TCP 631
            sniff(iface=iface, filter="port 631", prn=self.process_packet, store=False)

    def export(self, output_file, fmt):
        if fmt == "json":
            with open(output_file, "w") as f:
                json.dump({"alerts": self.alerts, "stats": self.stats}, f, indent=2)
        elif fmt == "csv":
            with open(output_file, "w", newline="") as f:
                fieldnames = ["timestamp", "severity", "category", "src_ip", "dst_ip", "protocol", "detail"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.alerts)
        
        print(f"\n[*] Analysis complete.")
        print(f"[*] UDP packets: {self.stats['udp_packets_seen']}, TCP packets: {self.stats['tcp_packets_seen']}")
        print(f"[*] Total alerts generated: {len(self.alerts)}")
        print(f"[*] Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect suspicious CUPS discovery and IPP traffic.")
    parser.add_argument("--iface", help="Interface for live capture")
    parser.add_argument("--pcap", help="Path to pcap file")
    parser.add_argument("--allowlist", default="", help="Comma-separated list of authorized printer IPs")
    parser.add_argument("--rate", type=int, default=5, help="Max packets per window before flagging flood")
    parser.add_argument("--window", type=int, default=10, help="Time window in seconds for flood detection")
    parser.add_argument("--max-size", type=int, default=1500, help="Max packet size before flagging (bytes)")
    parser.add_argument("--output", required=True, help="File to save alerts to")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    args = parser.parse_args()

    allowlist = [ip.strip() for ip in args.allowlist.split(",") if ip.strip()]
    detector = CupsDetector(allowlist, args.rate, args.window, args.max_size)
    
    if args.pcap:
        detector.run(pcap_file=args.pcap)
    elif args.iface:
        detector.run(iface=args.iface)
    else:
        print("Error: Must specify either --iface or --pcap")
        sys.exit(1)

    detector.export(args.output, args.format)