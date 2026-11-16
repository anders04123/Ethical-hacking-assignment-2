# Ethical-hacking-assignment-2

## Overview
This repo contains the attack and detections tools developed for an Ethical Hacking assignment on the CVE-2024-47177. The assignment project demonstrates how unauthenticated UDP printer discover traffic can be spoofed to inject malicious printer into a vulnerable cups browsed daemon. It provides Scapy-based detection tool to identify the suspicious activity

## Repo structure

*   **`cups_attack.py`**: A Scapy-based tool that crafts and sends malicious CUPS browse protocol packets over UDP/631.
*   **`cups_detector.py`**: A Scapy-based defensive tool that analyzes live traffic or `.pcap` files to detect unauthorized advertisements, malformed fields, and discovery floods.
*   **`requirements.txt`**: Python dependencies required to run the tools.
*   **`pcap/`**: Captured network traffic for analysis.
    *   `normal_traffic.pcap`: Baseline CUPS traffic.
    *   `attack_traffic.pcap`: The 4 crafted malicious packets.
    *   `victim.pcap`: Same attack packets arriving at the victim.
    *   `mitigated_attack.pcap`: The attack packets sent after applying the defense (showing the victim drops them).
*   **`logs/`**: Terminal outputs from the victim container.
    *   `victim_log.txt`: Shows the victim accepting the malicious printer queue.
    *   `victim_log_post_mitigation.txt`: Shows the victim denying the malicious packets after the mitigation is applied.
*   **`evidence/`**: Outputs from the detection tool.
    *   `alerts_normal.json`: Detection results from normal traffic (identifying false positives).
    *   `alerts_attack.json`: Detection results from the attack traffic (successful alerts).
    *   `screenshots/`: Wireshark captures and terminal screenshots.

## Lab Environment
*   **Attacker:** Kali Linux (`172.19.0.1`)
*   **Victim:** Vulhub CUPS Docker Container (`172.19.0.2`)
*   **Virtual Printer:** OpenPrinting `ippserver` (Port 12345)

## Usage

### 1. Requirements
Ensure Scapy is installed:
pip install -r requirements.txt

## 2. Run the attack tool
sudo python3 cups_attack.py --target 172.19.0.2 --my-ip 172.19.0.1 --variant all --output attack_traffic.pcap

## 3. Run the detection tool
python3 cups_detector.py --pcap pcap_files/attack_traffic.pcap --allowlist 172.19.0.2 --output evidence/alerts_attack.json

For live monitoring:
sudo python3 cups_detector.py --iface eth0 --allowlist 172.19.0.2 --output evidence/live_alerts.json