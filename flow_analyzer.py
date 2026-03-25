"""
flow_analyzer.py — Network Flow Analyzer
==========================================
This module tracks and analyzes network "flows" — complete conversations
between two devices on a network.

What is a Network Flow?
  Think of a network flow like a phone call between two people.
  When you open a website, your computer (caller) connects to a server
  (receiver). All the packets exchanged during that connection form
  a single "flow."

  A flow is uniquely identified by 5 pieces of information (the "5-tuple"):

    1. Source IP Address      — Who is sending? (e.g., 192.168.1.100)
    2. Destination IP Address — Who is receiving? (e.g., 142.250.80.46)
    3. Source Port            — Which app on the sender? (e.g., 52431)
    4. Destination Port       — Which service on the receiver? (e.g., 443)
    5. Protocol               — How are they talking? (TCP=6 or UDP=17)

  Example flow:
    Your browser      →  Google Server
    192.168.1.100:52431  →  142.250.80.46:443  (TCP)

  All packets with these exact 5 values belong to the same flow.

Why Track Flows?
  - See which connections transfer the most data
  - Identify long-running connections (streaming, downloads)
  - Detect suspicious patterns (port scans, data exfiltration)
  - Understand traffic composition (how many flows are HTTP vs DNS, etc.)

This module tracks:
  - Number of packets in each flow
  - Total bytes transferred in each flow
  - Start and end timestamps
  - Protocol breakdown
"""

from scapy.all import IP, TCP, UDP
from scapy.packet import Packet
from typing import Dict, Any, Optional, Tuple, List
import time


class Flow:
    """
    Represents a single network flow (a conversation between two endpoints).

    Each flow tracks statistics about the packets exchanged between
    a specific source and destination.
    """

    def __init__(self, src_ip: str, dst_ip: str, src_port: int,
                 dst_port: int, protocol: int):
        """
        Initialize a new flow with its 5-tuple.

        Args:
            src_ip:    Source IP address (who started the connection)
            dst_ip:    Destination IP address (who is being connected to)
            src_port:  Source port number (usually a random high port)
            dst_port:  Destination port number (the service port, e.g., 80, 443)
            protocol:  Protocol number (6 = TCP, 17 = UDP)
        """
        # ─── The 5-tuple that uniquely identifies this flow ───────
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        # ─── Flow statistics ──────────────────────────────────────
        self.packet_count = 0       # Total number of packets in this flow
        self.total_bytes = 0        # Total bytes transferred (all packets)

        # ─── Timestamps ──────────────────────────────────────────
        self.first_seen = None      # When the first packet was seen
        self.last_seen = None       # When the last packet was seen

    def update(self, packet_size: int, timestamp: float):
        """
        Update flow statistics when a new packet arrives.

        Called every time we see a packet belonging to this flow.

        Args:
            packet_size: Size of the packet in bytes
            timestamp:   When the packet was captured (epoch time)
        """
        self.packet_count += 1
        self.total_bytes += packet_size

        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp

    @property
    def duration(self) -> float:
        """
        Calculate how long this flow has been active (in seconds).

        Duration = time of last packet - time of first packet.
        A duration of 0 means only one packet was seen.
        """
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0

    @property
    def protocol_name(self) -> str:
        """Convert protocol number to human-readable name."""
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.protocol, f"Proto-{self.protocol}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to a dictionary for easy processing."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol_name,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration": round(self.duration, 3),
        }


class FlowAnalyzer:
    """
    Network Flow Analyzer — tracks and summarizes all network flows.

    Provides a summary table and flow-level statistics,
    grouping packets into flows by their 5-tuple.

    Usage:
        analyzer = FlowAnalyzer()

        for packet in packets:
            analyzer.process_packet(packet)

        analyzer.print_summary()
    """

    def __init__(self):
        """Initialize the flow analyzer with an empty flow table."""
        # ─── Flow table ──────────────────────────────────────────
        # Maps a flow key (string) to a Flow object
        # The key is built from the 5-tuple: "src_ip:port -> dst_ip:port (proto)"
        self.flows: Dict[str, Flow] = {}

        # ─── Overall statistics ───────────────────────────────────
        self.total_packets_processed = 0
        self.total_bytes_processed = 0

    def process_packet(self, packet: Packet) -> Optional[str]:
        """
        Process a single packet and update the corresponding flow.

        This is the main function of the flow analyzer. For each packet:
          1. Extract the 5-tuple from the packet
          2. Look up or create a flow entry in the flow table
          3. Update the flow's statistics (packet count, bytes, timestamps)

        Note: We use a "canonical" key that treats both directions of a
        connection as the same flow. So packets from A→B and B→A both
        count toward the same flow. This is because a single connection
        involves traffic in both directions.

        Args:
            packet: A Scapy Packet object

        Returns:
            The flow key (string) if the packet was processed,
            or None if the packet doesn't have IP+TCP/UDP layers.
        """
        # Only process packets that have an IP layer
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto

        # Extract port numbers from TCP or UDP layer
        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Create a canonical flow key
        # We sort the endpoints so that A→B and B→A map to the same flow
        flow_key = self._make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        # Get packet timestamp (Scapy stores it as a float)
        timestamp = float(packet.time)

        # Look up or create the flow
        if flow_key not in self.flows:
            # Determine the "canonical" direction (smaller IP first)
            if (src_ip, src_port) <= (dst_ip, dst_port):
                self.flows[flow_key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                self.flows[flow_key] = Flow(dst_ip, src_ip, dst_port, src_port, protocol)

        # Update flow statistics
        packet_size = len(packet)
        self.flows[flow_key].update(packet_size, timestamp)

        # Update overall statistics
        self.total_packets_processed += 1
        self.total_bytes_processed += packet_size

        return flow_key

    def _make_flow_key(self, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int, protocol: int) -> str:
        """
        Create a canonical flow key from a 5-tuple.

        "Canonical" means we always put the smaller (IP, port) pair first.
        This ensures that packets going A→B and B→A produce the same key.

        Example:
          192.168.1.100:52431 → 142.250.80.46:443 (TCP)
          and
          142.250.80.46:443 → 192.168.1.100:52431 (TCP)
          both produce:
          "142.250.80.46:443-192.168.1.100:52431-6"
        """
        # Sort endpoints to create a bidirectional key
        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        if endpoint1 > endpoint2:
            endpoint1, endpoint2 = endpoint2, endpoint1

        return f"{endpoint1[0]}:{endpoint1[1]}-{endpoint2[0]}:{endpoint2[1]}-{protocol}"

    def get_flows(self, sort_by: str = "total_bytes", reverse: bool = True) -> List[Flow]:
        """
        Get all flows, sorted by a specified metric.

        Args:
            sort_by:  Field to sort by. Options:
                      "total_bytes"   — Most data transferred first (default)
                      "packet_count"  — Most packets first
                      "duration"      — Longest-running first
            reverse:  Sort in descending order if True (default)

        Returns:
            A sorted list of Flow objects.
        """
        return sorted(
            self.flows.values(),
            key=lambda f: getattr(f, sort_by, 0),
            reverse=reverse,
        )

    def print_summary(self, top_n: int = 0, sort_by: str = "total_bytes"):
        """
        Print a formatted flow summary table.

        Displays all tracked flows with their statistics in a
        neatly formatted table. Optionally show only the top N flows.

        Args:
            top_n:    Number of top flows to show. 0 = show all.
            sort_by:  Sort criterion: "total_bytes", "packet_count", or "duration"
        """
        flows = self.get_flows(sort_by=sort_by)

        if top_n > 0:
            flows = flows[:top_n]

        print("\n" + "=" * 110)
        print("                              NETWORK FLOW SUMMARY TABLE")
        print("=" * 110)
        print(f"\n  Total Flows:    {len(self.flows)}")
        print(f"  Total Packets:  {self.total_packets_processed}")
        print(f"  Total Bytes:    {self._format_bytes(self.total_bytes_processed)}")
        print()

        # Table header
        header = (
            f"{'#':>4}  "
            f"{'Source IP':<18} "
            f"{'SPort':>6}  "
            f"{'Destination IP':<18} "
            f"{'DPort':>6}  "
            f"{'Proto':<6} "
            f"{'Packets':>8}  "
            f"{'Bytes':>12}  "
            f"{'Duration':>10}"
        )
        print(header)
        print("-" * 110)

        # Table rows
        for i, flow in enumerate(flows, 1):
            row = (
                f"{i:>4}  "
                f"{flow.src_ip:<18} "
                f"{flow.src_port:>6}  "
                f"{flow.dst_ip:<18} "
                f"{flow.dst_port:>6}  "
                f"{flow.protocol_name:<6} "
                f"{flow.packet_count:>8}  "
                f"{self._format_bytes(flow.total_bytes):>12}  "
                f"{flow.duration:>9.3f}s"
            )
            print(row)

        print("-" * 110)

        # Protocol breakdown
        self._print_protocol_breakdown()

    def _print_protocol_breakdown(self):
        """Print a summary of flows grouped by protocol."""
        proto_stats: Dict[str, Dict[str, int]] = {}

        for flow in self.flows.values():
            proto = flow.protocol_name
            if proto not in proto_stats:
                proto_stats[proto] = {"flows": 0, "packets": 0, "bytes": 0}
            proto_stats[proto]["flows"] += 1
            proto_stats[proto]["packets"] += flow.packet_count
            proto_stats[proto]["bytes"] += flow.total_bytes

        print("\n  PROTOCOL BREAKDOWN")
        print(f"  {'Protocol':<10} {'Flows':>8} {'Packets':>10} {'Bytes':>14}")
        print(f"  {'-' * 46}")

        for proto, stats in sorted(proto_stats.items()):
            print(
                f"  {proto:<10} "
                f"{stats['flows']:>8} "
                f"{stats['packets']:>10} "
                f"{self._format_bytes(stats['bytes']):>14}"
            )

        print("=" * 110)

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """
        Convert bytes to a human-readable format.

        Examples:
          1234       → "1.21 KB"
          1234567    → "1.18 MB"
          1234567890 → "1.15 GB"
        """
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.2f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"

    def get_summary_dict(self) -> Dict[str, Any]:
        """
        Return the flow summary as a dictionary (for programmatic access).

        Useful for integration with other modules or for saving results.
        """
        return {
            "total_flows": len(self.flows),
            "total_packets": self.total_packets_processed,
            "total_bytes": self.total_bytes_processed,
            "flows": [flow.to_dict() for flow in self.get_flows()],
        }
