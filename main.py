"""
main.py — Packet Analyzer Main Entry Point
============================================
This script connects all modules together:
  - capture.py     → Reads packets (from file or live)
  - parser.py      → Parses each packet into readable data
  - dpi_engine.py  → Classifies applications via Deep Packet Inspection
  - flow_analyzer.py → Tracks network flows and prints a summary

Supports two modes:
  1. Analyze a saved .pcap file:
     python main.py --file capture.pcap

  2. Live packet capture from a network interface:
     python main.py --live --interface "Wi-Fi" --count 100

"""

import argparse
import sys
from typing import List

from capture import read_pcap, live_capture, get_available_interfaces
from parser import parse_packet, format_packet_summary
from dpi_engine import DPIEngine
from flow_analyzer import FlowAnalyzer


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create the command-line argument parser.

    This defines all the options the user can pass when running the script.
    """
    parser = argparse.ArgumentParser(
        prog="Packet Analyzer",
        description=(
            "═══════════════════════════════════════════════\n"
            "      🔍 Network Packet Analyzer v2.0\n"
            "═══════════════════════════════════════════════\n"
            "Analyze network traffic from pcap files or live capture.\n"
            "Includes packet parsing, DPI, and flow analysis."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --file capture.pcap\n"
            "  %(prog)s --file capture.pcap --max 50 --no-dpi\n"
            "  %(prog)s --live --interface Wi-Fi --count 100\n"
            "  %(prog)s --live --count 50 --filter \"tcp port 80\"\n"
            "  %(prog)s --file capture.pcap --block-app YouTube --block-ip 10.0.0.1\n"
            "  %(prog)s --list-interfaces\n"
        ),
    )

    # ─── Mode selection ──────────────────────────────────────────
    mode_group = parser.add_mutually_exclusive_group()

    mode_group.add_argument(
        "--file", "-f",
        type=str,
        help="Path to a .pcap or .pcapng file to analyze (offline mode)"
    )

    mode_group.add_argument(
        "--live", "-l",
        action="store_true",
        help="Start live packet capture from a network interface"
    )

    mode_group.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit"
    )

    # ─── Capture options ─────────────────────────────────────────
    capture_group = parser.add_argument_group("Capture Options")

    capture_group.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Network interface for live capture (e.g., 'Wi-Fi', 'eth0')"
    )

    capture_group.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, default: 0)"
    )

    capture_group.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Capture timeout in seconds (for live capture)"
    )

    capture_group.add_argument(
        "--filter",
        type=str,
        default=None,
        help="BPF filter string (e.g., 'tcp port 80', 'host 8.8.8.8')"
    )

    # ─── Display options ─────────────────────────────────────────
    display_group = parser.add_argument_group("Display Options")

    display_group.add_argument(
        "--max", "-m",
        type=int,
        default=0,
        help="Maximum number of packets to display details for (0 = all)"
    )

    display_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress individual packet output, show only summaries"
    )

    display_group.add_argument(
        "--top-flows",
        type=int,
        default=20,
        help="Number of top flows to display in summary (default: 20)"
    )

    # ─── Analysis options ────────────────────────────────────────
    analysis_group = parser.add_argument_group("Analysis Options")

    analysis_group.add_argument(
        "--no-dpi",
        action="store_true",
        help="Disable Deep Packet Inspection (parse only)"
    )

    analysis_group.add_argument(
        "--no-flows",
        action="store_true",
        help="Disable flow analysis"
    )

    # ─── Blocking rules ──────────────────────────────────────────
    rules_group = parser.add_argument_group("Blocking Rules")

    rules_group.add_argument(
        "--block-ip",
        type=str,
        nargs="+",
        default=[],
        help="IP addresses to block (e.g., --block-ip 10.0.0.1 192.168.1.1)"
    )

    rules_group.add_argument(
        "--block-domain",
        type=str,
        nargs="+",
        default=[],
        help="Domains to block (e.g., --block-domain facebook.com *.tiktok.com)"
    )

    rules_group.add_argument(
        "--block-app",
        type=str,
        nargs="+",
        default=[],
        help="Applications to block (e.g., --block-app YouTube TikTok)"
    )

    rules_group.add_argument(
        "--block-port",
        type=int,
        nargs="+",
        default=[],
        help="Ports to block (e.g., --block-port 8080 3389)"
    )

    return parser


def print_banner():
    """Print a nice startup banner."""
    print()
    print("=" * 55)
    print("     Network Packet Analyzer v2.0")
    print("     Python Edition with DPI & Flow Analysis")
    print("=" * 55)
    print()


def analyze_packets(packets, args):
    """
    Run the full analysis pipeline on a list of packets.

    This connects all modules in sequence:
      1. parser.py     — Parse each packet
      2. dpi_engine.py — Classify each packet (if DPI enabled)
      3. flow_analyzer.py — Track flows (if flow analysis enabled)

    Args:
        packets: List of Scapy Packet objects
        args:    Parsed command-line arguments
    """
    # Initialize modules
    dpi = DPIEngine() if not args.no_dpi else None
    flow_analyzer = FlowAnalyzer() if not args.no_flows else None

    # Apply blocking rules to the DPI engine
    if dpi:
        for ip in args.block_ip:
            dpi.block_ip(ip)
        for domain in args.block_domain:
            dpi.block_domain(domain)
        for app in args.block_app:
            dpi.block_app(app)
        for port in args.block_port:
            dpi.block_port(port)

    # Determine how many packets to show details for
    max_display = args.max if args.max > 0 else len(packets)

    print(f"\n--- Processing {len(packets)} packets ---\n")

    blocked_count = 0
    forwarded_count = 0

    for i, packet in enumerate(packets):
        # Step 1: Parse the packet
        parsed = parse_packet(packet)

        # Step 2: DPI inspection
        dpi_result = None
        if dpi:
            dpi_result = dpi.inspect(packet)
            if dpi_result["action"] == "DROP":
                blocked_count += 1
            else:
                forwarded_count += 1

        # Step 3: Flow tracking
        if flow_analyzer:
            flow_analyzer.process_packet(packet)

        # Step 4: Display packet details (if not in quiet mode)
        if not args.quiet and i < max_display:
            print(format_packet_summary(parsed, i + 1))

            if dpi_result:
                print(f"\n  [DPI] App: {dpi_result['app']}", end="")
                if dpi_result["domain"]:
                    print(f" | Domain: {dpi_result['domain']}", end="")
                if dpi_result["protocol_type"] != "Unknown":
                    print(f" | Type: {dpi_result['protocol_type']}", end="")
                if dpi_result["action"] == "DROP":
                    print(f" | ⛔ BLOCKED: {dpi_result['block_reason']}", end="")
                print()

    # Print summaries
    print(f"\n{'=' * 55}")
    print(f"  Processing Complete")
    print(f"  Total Packets: {len(packets)}")
    if dpi:
        print(f"  Forwarded:     {forwarded_count}")
        print(f"  Blocked:       {blocked_count}")
    print(f"{'=' * 55}")

    # DPI statistics
    if dpi:
        dpi.print_statistics()

    # Flow summary
    if flow_analyzer:
        flow_analyzer.print_summary(top_n=args.top_flows)


def main():
    """
    Main entry point — parses arguments and runs the appropriate mode.

    This function orchestrates everything:
      1. Parse command-line arguments
      2. Capture packets (from file or live)
      3. Run the analysis pipeline
    """
    parser = create_argument_parser()
    args = parser.parse_args()

    print_banner()

    # ─── Mode: List interfaces ────────────────────────────────────
    if args.list_interfaces:
        print("Available network interfaces:")
        print("-" * 40)
        interfaces = get_available_interfaces()
        for iface in interfaces:
            print(f"  • {iface}")
        print()
        return

    # ─── Mode: Analyze PCAP file ──────────────────────────────────
    if args.file:
        print(f"Mode: Offline PCAP Analysis")
        print(f"File: {args.file}")
        print()

        try:
            packets = read_pcap(args.file)
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading pcap file: {e}")
            sys.exit(1)

        analyze_packets(packets, args)
        return

    # ─── Mode: Live capture ───────────────────────────────────────
    if args.live:
        print(f"Mode: Live Packet Capture")
        if args.interface:
            print(f"Interface: {args.interface}")
        if args.filter:
            print(f"Filter: {args.filter}")
        print()

        try:
            packets = live_capture(
                interface=args.interface,
                packet_count=args.count,
                timeout=args.timeout,
                bpf_filter=args.filter,
            )
        except PermissionError:
            print("Error: Live capture requires administrator/root privileges.")
            print("  Windows: Run CMD/PowerShell as Administrator")
            print("  Linux/macOS: Use sudo")
            sys.exit(1)
        except Exception as e:
            print(f"Error during capture: {e}")
            sys.exit(1)

        analyze_packets(packets, args)
        return

    # ─── No mode specified ────────────────────────────────────────
    parser.print_help()
    print("\nError: Please specify either --file or --live mode.")
    print("Use --list-interfaces to see available network interfaces.")
    sys.exit(1)


if __name__ == "__main__":
    main()
