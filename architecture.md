# 🏗️ Packet Analyzer — Architecture Guide

> A beginner-friendly explanation of how this Python packet analyzer works, from reading raw packets to identifying which app (Google, YouTube, etc.) generated the traffic.

---

## 1. Overall Architecture

Think of the packet analyzer as a **factory assembly line** for network packets:

```
┌─────────────────┐
│  PCAP File or    │  ← Saved .pcap file OR live network traffic
│  Live Interface  │
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│  capture.py      │  ← Reads packets (from file or sniffs live)
│  (Packet Capture)│
└───────┬─────────┘
        │  raw Scapy packets
        ▼
┌─────────────────┐
│  parser.py       │  ← Decodes packet layers (Ethernet, IP, TCP/UDP, DNS)
│  (Protocol Parse)│
└───────┬─────────┘
        │  parsed data (dict)
        ├──────────────────────┐
        ▼                      ▼
┌─────────────────┐   ┌─────────────────┐
│  dpi_engine.py   │   │ flow_analyzer.py│
│  (App Detection) │   │ (Flow Tracking) │
└───────┬─────────┘   └───────┬─────────┘
        │                      │
        └──────────┬───────────┘
                   ▼
        ┌─────────────────┐
        │     main.py      │  ← CLI + orchestration
        └─────────────────┘
```

### Key Idea

The system processes packets in **stages** (like a pipeline). Each stage does one job:

| Stage | Job | File |
|-------|-----|------|
| **Read** | Load packets from a .pcap file or sniff live traffic | `capture.py` |
| **Parse** | Decode Ethernet, IP, TCP/UDP headers into readable fields | `parser.py` |
| **Inspect** | Classify traffic (YouTube, Google, Netflix, etc.) via DPI | `dpi_engine.py` |
| **Track** | Group packets into flows and compute statistics | `flow_analyzer.py` |
| **Decide** | Forward or block based on user-defined rules | `dpi_engine.py` |
| **Report** | Print summaries, stats, and flow tables | `main.py` |

---

## 2. Packet Processing Pipeline

### Step 1: Reading Packets (`capture.py`)

The capture module supports two modes:

1. **Offline (PCAP file)** — Uses `scapy.rdpcap()` to load all packets from a `.pcap` or `.pcapng` file into memory.
2. **Live capture** — Uses `scapy.sniff()` to intercept packets in real-time from a network interface (requires administrator privileges).

Both modes return a list of Scapy `Packet` objects.

### Step 2: Parsing Packet Layers (`parser.py`)

Every network packet is like a set of **nested envelopes**:

```
┌─────────────────────────────────────┐
│ Ethernet Header (14 bytes)           │  ← MAC addresses + type
│  ┌─────────────────────────────────┐│
│  │ IP Header (20 bytes)            ││  ← IP addresses + protocol
│  │  ┌─────────────────────────────┐││
│  │  │ TCP/UDP Header (20/8 bytes) │││  ← Port numbers + flags
│  │  │  ┌─────────────────────────┐│││
│  │  │  │ Payload (variable)      ││││  ← The actual data (HTTP, TLS, etc.)
│  │  │  └─────────────────────────┘│││
│  │  └─────────────────────────────┘││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

The parser uses Scapy's built-in layer system (no manual byte-offset parsing needed):
1. Read **Ethernet** layer → extract source/destination MAC addresses
2. Read **IP** layer → extract source/destination IP addresses, TTL, protocol number
3. Read **TCP** layer → extract ports, sequence numbers, flags (SYN/ACK/FIN)
4. Or read **UDP** layer → extract ports
5. Read **DNS** / **ARP** / **ICMP** layers if present
6. Extract raw **payload** for DPI inspection

### Step 3: Deep Packet Inspection (`dpi_engine.py`)

The DPI engine inspects packet payloads to determine which application or service generated the traffic:

1. **TLS SNI Extraction** — When your browser connects to `https://www.youtube.com`, the first TLS handshake message ("Client Hello") contains the domain name in cleartext. The DPI engine parses this to identify the site.
2. **HTTP Host Header** — For unencrypted HTTP traffic, the `Host:` header tells us which website.
3. **DNS Query Parsing** — DNS lookups reveal which domain the user is trying to reach.
4. **Port-based Fallback** — Uses well-known port numbers (80 = HTTP, 443 = HTTPS, 53 = DNS) as a last resort.

After classification, the engine checks **blocking rules** (IPs, domains, apps, ports) and marks each packet as `FORWARD` or `DROP`.

### Step 4: Flow Analysis (`flow_analyzer.py`)

A **network flow** is a complete conversation between two devices, identified by 5 values (the "5-tuple"):

1. Source IP Address
2. Destination IP Address
3. Source Port
4. Destination Port
5. Protocol (TCP/UDP)

The flow analyzer groups packets by their 5-tuple and tracks:
- **Packet count** — How many packets were exchanged
- **Total bytes** — How much data was transferred
- **Duration** — How long the conversation lasted
- **Protocol breakdown** — TCP vs UDP distribution

### Step 5: Orchestration (`main.py`)

The main module ties everything together with a CLI interface:
- Parses command-line arguments using `argparse`
- Loads or captures packets via `capture.py`
- Runs parsing, DPI, and flow analysis in sequence
- Prints per-packet details, DPI results, and flow summaries

---

## 3. Role of Each Source File

| File | Purpose |
|------|---------|
| `main.py` | **Entry point**. CLI argument parsing, orchestrates the full pipeline, prints results. |
| `capture.py` | **Packet capture**. Reads `.pcap` files with `rdpcap()` and captures live traffic with `sniff()`. |
| `parser.py` | **Protocol decoder**. Extracts human-readable fields from each Scapy packet layer (Ethernet, IP, TCP, UDP, DNS, ARP, ICMP). |
| `dpi_engine.py` | **DPI engine**. Inspects payloads (TLS SNI, HTTP Host, DNS), classifies apps, enforces blocking rules. |
| `flow_analyzer.py` | **Flow tracker**. Groups packets into flows by 5-tuple, computes statistics, prints summary tables. |
| `generate_test_pcap.py` | **Test data generator**. Creates a `.pcap` file with sample TLS, HTTP, and DNS traffic for testing. |

---

## 4. How Packets Flow Through the System

Here's the complete journey of a single packet:

```
1. 📁 PCAP FILE on disk (or 📡 live network interface)
   │
   ▼
2. capture.read_pcap()  /  capture.live_capture()
   → Loads packets into a Python list of Scapy Packet objects
   │
   ▼
3. parser.parse_packet()
   → Ethernet layer: MAC addresses + EtherType
   → IP layer:       IP addresses, TTL, protocol
   → TCP/UDP layer:  ports, seq/ack numbers, flags
   → Payload:        raw bytes for DPI
   → Returns a dictionary with all parsed fields
   │
   ▼
4. dpi_engine.inspect()
   → Extracts 5-tuple from the packet
   → Checks if this connection was already classified
   → If not, tries TLS SNI → HTTP Host → DNS → port fallback
   → Maps domain to app (e.g., "www.youtube.com" → YouTube)
   → Checks blocking rules → FORWARD or DROP
   │
   ▼
5. flow_analyzer.process_packet()
   → Creates canonical flow key from 5-tuple
   → Updates flow statistics (packet count, bytes, timestamps)
   │
   ▼
6. main.analyze_packets()
   → Prints packet details and DPI results
   → After all packets: prints DPI statistics and flow summary table
```

### Summary

The packet analyzer reads captured network traffic, understands what each packet contains (which IP is talking to which IP, on what port, using what protocol), figures out which application or website generated that traffic, and can selectively block or forward packets based on configurable rules. It's like a **smart firewall** that understands the difference between YouTube and Google traffic.
