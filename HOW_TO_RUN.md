# 📝 How to Run & Test the Packet Analyzer

This guide covers installation, running the analyzer, generating test data, and using Wireshark to create your own capture files.

---

## 1. Prerequisites

| Requirement | Purpose |
|-------------|---------|
| **Python 3.8+** | Runtime for the analyzer |
| **Scapy** (`pip install scapy`) | Packet parsing and capture library |
| **Npcap** (Windows) or **libpcap** (Linux/macOS) | Required only for **live capture** |
| **Wireshark** (optional) | Create and inspect `.pcap` files |

---

## 2. Installation

```bash
# Clone or download the project
cd Packet_analyzer

# Create a virtual environment (recommended)
python -m venv .venv

# Activate the virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install scapy
```

### Install Npcap (Windows — for live capture only)

1. Download Npcap from [https://npcap.com/](https://npcap.com/)
2. Run the installer
3. Check **"Install Npcap in WinPcap API-compatible Mode"** during setup
4. Restart your terminal

> **Note:** Npcap is NOT required for analyzing `.pcap` files. It's only needed for live capture (`--live` mode).

---

## 3. Running the Analyzer

### 3.1 Analyze a PCAP File

```bash
# Full analysis with packet details + DPI + flow summary
python main.py --file test_dpi.pcap

# Quiet mode — only show summaries (no per-packet output)
python main.py --file test_dpi.pcap --quiet

# Show only the first 10 packets
python main.py --file test_dpi.pcap --max 10

# Skip DPI (parse packets only)
python main.py --file test_dpi.pcap --no-dpi

# Skip flow analysis
python main.py --file test_dpi.pcap --no-flows
```

### 3.2 Live Packet Capture

> ⚠️ **Requires Administrator/root privileges and Npcap/libpcap installed.**

```bash
# Windows: Open PowerShell as Administrator
# Linux/macOS: Use sudo

# Capture 50 packets from default interface
python main.py --live --count 50

# Capture from a specific interface
python main.py --live --interface "Wi-Fi" --count 100

# Capture with a BPF filter (only TCP port 80)
python main.py --live --filter "tcp port 80" --count 30

# Capture with a timeout (stop after 30 seconds)
python main.py --live --timeout 30
```

### 3.3 List Available Interfaces

```bash
python main.py --list-interfaces
```

### 3.4 Traffic Filtering (Blocking)

```bash
# Block traffic from/to specific IPs
python main.py --file test_dpi.pcap --block-ip 192.168.1.50

# Block a specific application
python main.py --file test_dpi.pcap --block-app YouTube

# Block domains (supports wildcards)
python main.py --file test_dpi.pcap --block-domain "*.facebook.com"

# Block traffic on a specific port
python main.py --file test_dpi.pcap --block-port 8080
```

---

## 4. Generate Test Data

The project includes a test PCAP generator:

```bash
python generate_test_pcap.py
```

This creates `test_dpi.pcap` with:
- **16 TLS connections** with SNI (Google, YouTube, Facebook, Netflix, etc.)
- **2 HTTP connections** with Host headers
- **4 DNS queries** (google.com, youtube.com, facebook.com, twitter.com)
- **5 packets from a blocked IP** (`192.168.1.50`)

---

## 5. Using Wireshark to Create PCAP Files

[Wireshark](https://www.wireshark.org/) is a free, open-source network analyzer. You can use it to capture your own network traffic and save it as `.pcap` files for analysis.

### 5.1 Capture Traffic with Wireshark

1. **Open Wireshark**
2. **Select your network interface** (e.g., "Wi-Fi" or "Ethernet")
3. **Start capturing** — click the blue shark fin button (or double-click the interface)
4. **Browse the web** or use any network application to generate traffic
5. **Stop capturing** — click the red square button
6. **Save the capture:**
   - `File` → `Save As...`
   - Choose format: **Wireshark/tcpdump/... - pcap**
   - Save as `my_capture.pcap`

### 5.2 Analyze the Wireshark Capture

```bash
python main.py --file my_capture.pcap
```

### 5.3 Filter in Wireshark Before Saving

You can apply Wireshark display filters before saving to focus on specific traffic:

| Filter | What it captures |
|--------|-----------------|
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `dns` | Only DNS queries/responses |
| `http` | Only HTTP traffic |
| `tls.handshake.type == 1` | Only TLS Client Hello (SNI visible) |
| `ip.addr == 8.8.8.8` | Only traffic to/from Google DNS |
| `tcp.port == 443` | Only HTTPS traffic |

After filtering:
1. `File` → `Export Specified Packets...`
2. Make sure "Displayed" is selected (not "All packets")
3. Save as `.pcap`

### 5.4 Quick Capture with tcpdump (Linux/macOS)

```bash
# Capture 100 packets and save to file
sudo tcpdump -c 100 -w my_capture.pcap

# Capture only DNS traffic
sudo tcpdump -c 50 port 53 -w dns_capture.pcap

# Capture only HTTPS traffic
sudo tcpdump -c 100 port 443 -w https_capture.pcap
```

### 5.5 Quick Capture with tshark (CLI Wireshark)

```bash
# Capture 50 packets
tshark -c 50 -w my_capture.pcap

# Capture with a display filter
tshark -c 100 -f "tcp port 80" -w http_capture.pcap
```

---

## 6. Verify Everything Works

Run through these checks to confirm the analyzer is fully operational:

```bash
# 1. Generate test data
python generate_test_pcap.py

# 2. Run full analysis
python main.py --file test_dpi.pcap

# 3. Run quiet mode (summary only)
python main.py --file test_dpi.pcap --quiet

# 4. Test DPI blocking
python main.py --file test_dpi.pcap --block-app YouTube --quiet

# 5. Test IP blocking
python main.py --file test_dpi.pcap --block-ip 192.168.1.50 --quiet

# 6. Test with no DPI
python main.py --file test_dpi.pcap --no-dpi --quiet

# 7. List interfaces
python main.py --list-interfaces
```

**Expected results:**
- ✅ Step 1: Creates `test_dpi.pcap` with ~77 packets
- ✅ Step 2: Shows packet details + DPI classifications + flow summary table
- ✅ Step 3: Shows only statistics and flow table
- ✅ Step 4: YouTube packets appear as "⛔ BLOCKED"
- ✅ Step 5: Packets from `192.168.1.50` appear as "⛔ BLOCKED"
- ✅ Step 6: Shows parsed packets without app classification
- ✅ Step 7: Lists available network interfaces

---

## 7. Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'scapy'` | Run `pip install scapy` (make sure your venv is activated) |
| `WARNING: No libpcap provider available` | Install Npcap (Windows) or libpcap (Linux). Only needed for live capture — pcap file analysis works without it. |
| `PermissionError` during live capture | Run as Administrator (Windows) or use `sudo` (Linux/macOS) |
| `FileNotFoundError` for pcap file | Check the file path. Run `python generate_test_pcap.py` to create a test file. |
| Unicode/emoji display issues in terminal | Use Windows Terminal or VS Code terminal instead of legacy CMD. |
