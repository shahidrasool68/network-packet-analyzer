"""
capture.py — Packet Capture Module
====================================
This module handles capturing network packets from two sources:
  1. Reading packets from a saved .pcap file (offline analysis)
  2. Sniffing packets in real-time from a network interface (live capture)

It uses the Scapy library, which is a powerful Python tool for
working with network packets. Scapy handles all the low-level
details of reading pcap files and capturing live traffic.


"""

from scapy.all import rdpcap, sniff, conf
from typing import Callable, Optional, List
from scapy.packet import Packet


def read_pcap(file_path: str) -> List[Packet]:
    """
    Read all packets from a .pcap file and return them as a list.

    A .pcap file is the standard format for captured network traffic.
    Tools like Wireshark, tcpdump, and tshark save captures in this format.

    Scapy's rdpcap() handles all the binary file format details automatically.

    Args:
        file_path: Path to the .pcap or .pcapng file
                   Example: "capture.pcap" or "test_traffic.pcapng"

    Returns:
        A list of Scapy Packet objects, each representing one captured packet.
        Each packet contains all the protocol layers (Ethernet, IP, TCP, etc.)

    Raises:
        FileNotFoundError: If the pcap file doesn't exist
        Scapy_Exception: If the file is not a valid pcap format
    """
    print(f"[Capture] Reading packets from: {file_path}")

    # rdpcap reads the entire file into memory
    # For very large files, consider using PcapReader for streaming
    packets = rdpcap(file_path)

    print(f"[Capture] Loaded {len(packets)} packets from file")
    return list(packets)


def live_capture(
    interface: Optional[str] = None,
    packet_count: int = 0,
    timeout: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    callback: Optional[Callable[[Packet], None]] = None,
) -> List[Packet]:
    """
    Capture packets live from a network interface.

    This is like running Wireshark in capture mode. Packets are
    intercepted as they travel through the selected network interface
    (e.g., your Wi-Fi or Ethernet adapter).

    Uses Scapy's sniff() function for live packet capture.

    Args:
        interface:    Name of the network interface to capture on.
                      Examples: "eth0" (Linux), "Wi-Fi" (Windows), "en0" (macOS)
                      If None, Scapy auto-selects the default interface.

        packet_count: Number of packets to capture before stopping.
                      0 means capture indefinitely (until timeout or Ctrl+C).

        timeout:      Maximum number of seconds to capture.
                      None means no time limit.

        bpf_filter:   Berkeley Packet Filter string to filter traffic.
                      Examples:
                        "tcp"             → only TCP packets
                        "udp port 53"    → only DNS traffic
                        "host 8.8.8.8"   → only traffic to/from Google DNS
                        "tcp port 80"    → only HTTP traffic

        callback:     Optional function called for each captured packet.
                      Useful for real-time processing (e.g., parse + inspect
                      each packet as it arrives, instead of waiting for all).

    Returns:
        A list of all captured Scapy Packet objects.

    Note:
        Live capture usually requires administrator/root privileges.
        On Windows: Run as Administrator
        On Linux/macOS: Use sudo
    """
    # Build informative log message
    iface_name = interface or "default"
    print(f"[Capture] Starting live capture on interface: {iface_name}")

    if bpf_filter:
        print(f"[Capture] BPF filter: {bpf_filter}")
    if packet_count > 0:
        print(f"[Capture] Will capture {packet_count} packets")
    if timeout:
        print(f"[Capture] Timeout: {timeout} seconds")

    print("[Capture] Press Ctrl+C to stop capture...\n")

    # Build the sniff() keyword arguments
    sniff_kwargs = {
        "count": packet_count,  # 0 = indefinite
        "store": True,          # Keep packets in memory to return them
    }

    if interface:
        sniff_kwargs["iface"] = interface
    if timeout:
        sniff_kwargs["timeout"] = timeout
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter
    if callback:
        # prn (print) is Scapy's name for the per-packet callback
        sniff_kwargs["prn"] = callback

    # Start capturing — this blocks until count/timeout is reached or Ctrl+C
    packets = sniff(**sniff_kwargs)

    print(f"\n[Capture] Captured {len(packets)} packets")
    return list(packets)


def get_available_interfaces() -> List[str]:
    """
    List all available network interfaces on this machine.

    Useful for showing the user which interfaces they can capture on.
    Each interface represents a network adapter (Wi-Fi, Ethernet, loopback, etc.)

    Returns:
        A list of interface names (strings).
    """
    try:
        # conf.ifaces gives us all network interfaces
        # IFACES is a dictionary-like object with interface info
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        return interfaces
    except Exception:
        return ["Could not enumerate interfaces"]
