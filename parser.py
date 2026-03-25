"""
parser.py — Packet Parsing Module
===================================
This module extracts human-readable information from raw network packets.

When a packet arrives, it's just a sequence of bytes. This module peels
apart those bytes layer by layer (like opening nested envelopes) to extract:
  - Ethernet layer: MAC addresses
  - IP layer: IP addresses, TTL, protocol
  - Transport layer: TCP or UDP ports, flags
  - Payload: The actual data being transmitted

With Scapy, the packets are already parsed into layers.
We simply access the fields using Scapy's layer system.
"""

from scapy.all import (
    Ether,    # Ethernet layer
    IP,       # IPv4 layer
    IPv6,     # IPv6 layer
    TCP,      # TCP layer
    UDP,      # UDP layer
    DNS,      # DNS layer
    ICMP,     # ICMP layer
    Raw,      # Raw payload data
    ARP,      # ARP layer
)
from scapy.packet import Packet
from typing import Dict, Any, Optional


def parse_packet(packet: Packet) -> Dict[str, Any]:
    """
    Parse a single Scapy packet and extract all meaningful fields.

    Scapy has already decoded all protocol layers for us, so we just read
    the fields from the appropriate layer objects.

    Args:
        packet: A Scapy Packet object (from capture or pcap file)

    Returns:
        A dictionary containing all parsed fields. Example:
        {
            "timestamp": 1678901234.567,
            "ethernet": {"src_mac": "aa:bb:cc:dd:ee:ff", ...},
            "ip": {"src_ip": "192.168.1.1", ...},
            "tcp": {"src_port": 443, ...},
            "payload": {"length": 256, "preview": "16 03 01 ..."}
        }
    """
    result = {
        "timestamp": float(packet.time),  # Epoch timestamp
        "length": len(packet),            # Total packet length in bytes
        "layers": [],                     # List of protocol layer names
    }

    # ─── Layer 1: Ethernet ─────────────────────────────────────────
    # The outermost envelope. Contains MAC addresses and tells us
    # what type of content is inside (IPv4, IPv6, ARP, etc.)
    if packet.haslayer(Ether):
        eth = packet[Ether]
        result["ethernet"] = {
            "src_mac": eth.src,       # Source MAC address (e.g., "aa:bb:cc:dd:ee:ff")
            "dst_mac": eth.dst,       # Destination MAC address
            "ether_type": hex(eth.type),  # Type code (0x800 = IPv4, 0x86dd = IPv6)
        }
        result["layers"].append("Ethernet")

    # ─── Layer 2: IP (Internet Protocol) ───────────────────────────
    # Contains the IP addresses and routing information.
    # This tells us WHO is talking to WHOM across the internet.
    if packet.haslayer(IP):
        ip = packet[IP]
        result["ip"] = {
            "version": ip.version,      # 4 for IPv4
            "src_ip": ip.src,           # Source IP (e.g., "192.168.1.100")
            "dst_ip": ip.dst,           # Destination IP (e.g., "8.8.8.8")
            "protocol": ip.proto,       # Protocol number (6=TCP, 17=UDP, 1=ICMP)
            "protocol_name": _protocol_name(ip.proto),  # Human-readable name
            "ttl": ip.ttl,              # Time To Live (hop count)
            "length": ip.len,           # Total IP packet length
            "identification": ip.id,    # Fragment identification
        }
        result["layers"].append("IPv4")

    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        result["ip"] = {
            "version": 6,
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "protocol": ipv6.nh,        # Next Header (similar to protocol)
            "protocol_name": _protocol_name(ipv6.nh),
            "hop_limit": ipv6.hlim,     # Equivalent to TTL in IPv4
            "flow_label": ipv6.fl,      # Flow label for QoS
        }
        result["layers"].append("IPv6")

    # ─── Layer 3: TCP (Transmission Control Protocol) ──────────────
    # TCP provides reliable, ordered delivery of data.
    # Used by HTTP, HTTPS, SSH, FTP, and most web traffic.
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["tcp"] = {
            "src_port": tcp.sport,         # Source port (client's random port)
            "dst_port": tcp.dport,         # Destination port (80=HTTP, 443=HTTPS)
            "seq_number": tcp.seq,         # Sequence number (for ordering)
            "ack_number": tcp.ack,         # Acknowledgment number
            "flags": str(tcp.flags),       # TCP flags as string (e.g., "SA" for SYN-ACK)
            "flags_detail": _tcp_flags_detail(tcp.flags),  # Expanded flag names
            "window_size": tcp.window,     # Flow control window
        }
        result["layers"].append("TCP")

    # ─── Layer 3: UDP (User Datagram Protocol) ─────────────────────
    # UDP is faster but unreliable (no guaranteed delivery).
    # Used by DNS, video streaming, gaming, VoIP.
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["udp"] = {
            "src_port": udp.sport,     # Source port
            "dst_port": udp.dport,     # Destination port (53=DNS, 443=QUIC)
            "length": udp.len,         # Length of UDP header + payload
        }
        result["layers"].append("UDP")

    # ─── Layer 3: ICMP ─────────────────────────────────────────────
    # ICMP is used for network diagnostics (ping, traceroute).
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["icmp"] = {
            "type": icmp.type,         # Message type (8=Echo Request, 0=Echo Reply)
            "code": icmp.code,         # Subtype
            "type_name": _icmp_type_name(icmp.type),
        }
        result["layers"].append("ICMP")

    # ─── Layer 2 Alt: ARP ───────────────────────────────────────────
    # ARP maps IP addresses to MAC addresses on a local network.
    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["arp"] = {
            "operation": "request" if arp.op == 1 else "reply",
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
        }
        result["layers"].append("ARP")

    # ─── Layer 3: DNS ──────────────────────────────────────────────
    # DNS translates domain names (google.com) to IP addresses.
    if packet.haslayer(DNS):
        dns = packet[DNS]
        result["dns"] = _parse_dns(dns)
        result["layers"].append("DNS")

    # ─── Payload (Raw Data) ────────────────────────────────────────
    # Whatever data is left after all protocol headers are stripped.
    # This could be HTTP content, encrypted TLS data, etc.
    if packet.haslayer(Raw):
        raw = packet[Raw]
        payload_bytes = bytes(raw.load)
        result["payload"] = {
            "length": len(payload_bytes),
            "preview": _hex_preview(payload_bytes, 32),  # First 32 bytes as hex
            "ascii_preview": _ascii_preview(payload_bytes, 64),  # Printable chars
        }
        result["layers"].append("Payload")

    return result


def get_five_tuple(packet: Packet) -> Optional[Dict[str, Any]]:
    """
    Extract the 5-tuple from a packet.

    The 5-tuple uniquely identifies a network "conversation" (flow):
      1. Source IP address
      2. Destination IP address
      3. Source port number
      4. Destination port number
      5. Protocol (TCP=6 or UDP=17)

    Args:
        packet: A Scapy Packet object

    Returns:
        Dictionary with the 5 fields, or None if the packet
        doesn't have IP + TCP/UDP layers (e.g., ARP packets).
    """
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    protocol = ip.proto

    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        # No transport layer (e.g., ICMP) — ports are 0
        pass

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "protocol_name": _protocol_name(protocol),
    }


def format_packet_summary(parsed: Dict[str, Any], packet_num: int) -> str:
    """
    Format a parsed packet into a human-readable summary string.

    Formats parsed packet data into a human-readable multi-line string.

    Args:
        parsed:     Dictionary from parse_packet()
        packet_num: Sequential packet number (for display)

    Returns:
        A formatted multi-line string ready to print.
    """
    lines = []
    lines.append(f"\n{'='*10} Packet #{packet_num} {'='*10}")
    lines.append(f"Length: {parsed['length']} bytes")
    lines.append(f"Layers: {' → '.join(parsed['layers'])}")

    # Ethernet layer
    if "ethernet" in parsed:
        eth = parsed["ethernet"]
        lines.append(f"\n[Ethernet]")
        lines.append(f"  Source MAC:      {eth['src_mac']}")
        lines.append(f"  Destination MAC: {eth['dst_mac']}")
        lines.append(f"  EtherType:       {eth['ether_type']}")

    # IP layer
    if "ip" in parsed:
        ip = parsed["ip"]
        lines.append(f"\n[IPv{ip['version']}]")
        lines.append(f"  Source IP:      {ip['src_ip']}")
        lines.append(f"  Destination IP: {ip['dst_ip']}")
        lines.append(f"  Protocol:       {ip['protocol_name']}")
        if "ttl" in ip:
            lines.append(f"  TTL:            {ip['ttl']}")

    # TCP layer
    if "tcp" in parsed:
        tcp = parsed["tcp"]
        lines.append(f"\n[TCP]")
        lines.append(f"  Source Port:      {tcp['src_port']}")
        lines.append(f"  Destination Port: {tcp['dst_port']}")
        lines.append(f"  Seq Number:       {tcp['seq_number']}")
        lines.append(f"  Ack Number:       {tcp['ack_number']}")
        lines.append(f"  Flags:            {tcp['flags_detail']}")

    # UDP layer
    if "udp" in parsed:
        udp = parsed["udp"]
        lines.append(f"\n[UDP]")
        lines.append(f"  Source Port:      {udp['src_port']}")
        lines.append(f"  Destination Port: {udp['dst_port']}")

    # DNS layer
    if "dns" in parsed:
        dns = parsed["dns"]
        lines.append(f"\n[DNS]")
        lines.append(f"  Type:  {dns.get('type', 'unknown')}")
        if dns.get("queries"):
            for q in dns["queries"]:
                lines.append(f"  Query: {q}")

    # Payload
    if "payload" in parsed:
        pl = parsed["payload"]
        lines.append(f"\n[Payload]")
        lines.append(f"  Length:  {pl['length']} bytes")
        lines.append(f"  Hex:     {pl['preview']}")
        if pl["ascii_preview"]:
            lines.append(f"  ASCII:   {pl['ascii_preview']}")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# Private Helper Functions
# ═══════════════════════════════════════════════════════════════════


def _protocol_name(proto_num: int) -> str:
    """
    Convert a protocol number to a human-readable name.
    Maps IANA protocol numbers to readable names.
    """
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        58: "ICMPv6",
        89: "OSPF",
    }
    return protocols.get(proto_num, f"Unknown({proto_num})")


def _tcp_flags_detail(flags) -> str:
    """
    Expand TCP flag bits into readable names.
    Expands single-character TCP flags into their full names.

    TCP flags control the connection lifecycle:
      SYN = "I want to start a connection"
      ACK = "I acknowledge your data"
      FIN = "I want to close the connection"
      RST = "Reset / abort the connection"
      PSH = "Push this data to the application immediately"
      URG = "This data is urgent, process it first"
    """
    flag_str = str(flags)
    flag_names = []

    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    for char in flag_str:
        if char in flag_map:
            flag_names.append(flag_map[char])

    return " ".join(flag_names) if flag_names else "none"


def _icmp_type_name(icmp_type: int) -> str:
    """Convert ICMP type number to a human-readable name."""
    types = {
        0: "Echo Reply (ping response)",
        3: "Destination Unreachable",
        8: "Echo Request (ping)",
        11: "Time Exceeded (traceroute)",
    }
    return types.get(icmp_type, f"Type {icmp_type}")


def _parse_dns(dns_layer) -> Dict[str, Any]:
    """
    Extract information from a DNS layer.
    """
    result = {}

    # DNS has a QR bit: 0 = query, 1 = response
    if dns_layer.qr == 0:
        result["type"] = "query"
    else:
        result["type"] = "response"

    # Extract query names
    queries = []
    if dns_layer.qdcount and dns_layer.qd:
        qd = dns_layer.qd
        while qd:
            name = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
            queries.append(name.rstrip("."))
            qd = qd.payload if hasattr(qd, "payload") and qd.payload else None
            # Only process the first query to avoid infinite loop
            break

    result["queries"] = queries

    return result


def _hex_preview(data: bytes, max_bytes: int = 32) -> str:
    """
    Convert bytes to a hex string preview.
    Shows the first max_bytes bytes as hex pairs.
    Example: "16 03 01 00 f1 01 00 00 ed ..."
    """
    preview = " ".join(f"{b:02x}" for b in data[:max_bytes])
    if len(data) > max_bytes:
        preview += " ..."
    return preview


def _ascii_preview(data: bytes, max_chars: int = 64) -> str:
    """
    Extract printable ASCII characters from payload data.
    Non-printable characters are replaced with dots.
    This helps identify protocols (e.g., "GET / HTTP/1.1" for HTTP).
    """
    result = ""
    for b in data[:max_chars]:
        if 32 <= b <= 126:  # Printable ASCII range
            result += chr(b)
        else:
            result += "."

    if len(data) > max_chars:
        result += "..."
    return result
