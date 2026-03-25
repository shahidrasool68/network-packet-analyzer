# 🔍 Network Packet Analyzer

> A comprehensive network traffic analysis tool with Deep Packet Inspection (DPI), flow tracking, and application classification — built in Python using Scapy.

---

## 📋 Project Overview

This project is a **network packet analyzer** that reads captured network traffic and performs:

- **Packet Parsing** — Decodes Ethernet, IP, TCP, UDP, ICMP, DNS, and ARP headers
- **Deep Packet Inspection** — Identifies applications (YouTube, Google, Netflix, etc.) by inspecting TLS SNI, HTTP Host headers, and DNS queries
- **Flow Analysis** — Tracks network conversations using the 5-tuple (source/destination IP, ports, protocol)
- **Traffic Filtering** — Blocks traffic by IP, domain, application, or port

---

## ✨ Features

- 📦 **PCAP File Analysis** — Read and analyze `.pcap` files from Wireshark or tcpdump
- 📡 **Live Capture** — Sniff packets in real-time from any network interface
- 🔬 **Deep Packet Inspection** — TLS SNI extraction, HTTP Host parsing, DNS query analysis
- 🏷️ **Application Classification** — Identifies 20+ applications (Google, YouTube, Netflix, etc.)
- 📊 **Flow Analysis** — Track flows by 5-tuple with packet counts, byte totals, and duration
- 🛡️ **Traffic Filtering** — Block IPs, domains, apps, or ports via CLI or programmatically
- 📈 **Statistics Reports** — Protocol breakdown, app distribution, flow summaries

---

## 🏗️ Architecture Diagram

```
                        ┌─────────────────────┐
                        │   PCAP File / Live   │
                        │     Network Feed     │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │    capture.py        │
                        │  (Packet Capture)    │
                        └──────────┬──────────┘
                                   │  raw packets
                        ┌──────────▼──────────┐
                        │     parser.py        │
                        │  (Protocol Parsing)  │
                        └──────────┬──────────┘
                                   │  parsed data
                    ┌──────────────┼──────────────┐
                    │              │               │
         ┌──────────▼──────┐  ┌───▼───────────┐  │
         │  dpi_engine.py   │  │ flow_analyzer │  │
         │  (App Detection) │  │ (Flow Tracking)│  │
         └──────────┬──────┘  └───┬───────────┘  │
                    │              │               │
                    └──────────────┼───────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │     main.py          │
                        │  (CLI Integration)   │
                        └─────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** required
- **Administrator/root access** required for live capture

### Setup

```bash
# Clone the repository
git clone https://github.com/your-username/network-packet-analyzer.git
cd network-packet-analyzer

# Install Python dependencies
pip install scapy

# (Optional) Install Npcap for live capture on Windows
# Download from: https://npcap.com/
```

---

## 📖 Usage Examples

### 1. Analyze a PCAP File

```bash
# Basic analysis — parses, inspects, and tracks all packets
python main.py --file capture.pcap

# Show only the first 20 packets
python main.py --file capture.pcap --max 20

# Quiet mode — show only summary statistics
python main.py --file capture.pcap --quiet

# Disable DPI (parse only, no app classification)
python main.py --file capture.pcap --no-dpi
```

### 2. Live Packet Capture

```bash
# Capture 100 packets from the default interface
python main.py --live --count 100

# Capture from a specific interface
python main.py --live --interface "Wi-Fi" --count 50

# Capture with a BPF filter (only HTTP traffic)
python main.py --live --filter "tcp port 80" --count 30

# Capture with a 60-second timeout
python main.py --live --timeout 60
```

### 3. Traffic Filtering (Blocking)

```bash
# Block specific IPs
python main.py --file capture.pcap --block-ip 10.0.0.1 192.168.1.100

# Block specific applications
python main.py --file capture.pcap --block-app YouTube TikTok

# Block domains (supports wildcards)
python main.py --file capture.pcap --block-domain "facebook.com" "*.tiktok.com"

# Block specific ports
python main.py --file capture.pcap --block-port 8080 3389
```

### 4. List Network Interfaces

```bash
python main.py --list-interfaces
```

---

## 📊 Flow Analyzer Explained

### What is a Network Flow?

A **network flow** is a sequence of packets that belong to the same conversation between two devices. It's identified by 5 values (the "5-tuple"):

| Field | Description | Example |
|-------|-------------|---------|
| Source IP | Who is sending | `192.168.1.100` |
| Destination IP | Who is receiving | `142.250.80.46` |
| Source Port | Sender's app port | `52431` |
| Destination Port | Service port | `443` (HTTPS) |
| Protocol | Communication method | `TCP` (6) |

### What the Flow Analyzer Tracks

For each unique flow, the analyzer tracks:
- **Packet count** — How many packets were exchanged
- **Total bytes** — How much data was transferred
- **Duration** — How long the conversation lasted
- **Protocol** — Whether it's TCP, UDP, or other

### Sample Output

```
══════════════════════════════════════════════════════════════
                    NETWORK FLOW SUMMARY TABLE
══════════════════════════════════════════════════════════════

  Total Flows:    15
  Total Packets:  234
  Total Bytes:    125.67 KB

   #  Source IP          SPort  Destination IP     DPort  Proto  Packets         Bytes    Duration
──────────────────────────────────────────────────────────────
   1  192.168.1.100         52431  142.250.80.46         443  TCP       45      23.45 KB     2.341s
   2  192.168.1.100         49872  104.244.42.129         443  TCP       32      12.78 KB     1.892s
   3  192.168.1.100         55123  8.8.8.8                53  UDP       18       1.23 KB     0.456s
```

---

## 📁 Project Structure

```
Packet_analyzer/
├── main.py                   # 🎯 Main entry point (CLI integration)
├── capture.py                # 📡 Packet capture (pcap + live)
├── parser.py                 # 🔍 Protocol parsing (Eth/IP/TCP/UDP/DNS)
├── dpi_engine.py             # 🧠 Deep Packet Inspection engine
├── flow_analyzer.py          # 📊 Network flow tracking & analysis
├── generate_test_pcap.py     # 🧪 Test PCAP file generator
├── architecture.md           # 🏗️ Architecture documentation
├── HOW_TO_RUN.md             # 📝 How to run and test guide
└── README.md                 # 📄 This file
```

---

## 🔮 Future Improvements

- **IPv6 Support** — Extend DPI and flow analysis to handle IPv6 traffic
- **QUIC Protocol** — Full QUIC/HTTP3 dissection (currently simplified)
- **GUI Dashboard** — Web-based real-time visualization with charts
- **Alerting System** — Configurable alerts for suspicious patterns
- **GeoIP Mapping** — Map IP addresses to geographic locations
- **Export Formats** — CSV, JSON, and PDF export of analysis results
- **Bandwidth Monitoring** — Real-time bandwidth graphs per application
- **Machine Learning** — Anomaly detection using traffic patterns
- **Plugin System** — Custom protocol analyzers as plugins
- **Database Storage** — Store flow data in SQLite/PostgreSQL for historical analysis

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
