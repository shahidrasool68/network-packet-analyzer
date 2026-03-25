"""
dpi_engine.py — Deep Packet Inspection Engine
===============================================
This module performs Deep Packet Inspection (DPI) — analyzing the
*content* of network packets to identify which application or service
generated them.

What is DPI?
  Normal firewalls only look at IP addresses and port numbers.
  DPI goes deeper — it inspects the actual payload data to figure out
  what application is being used. For example:
    - Port 443 could be HTTPS to Google, YouTube, or Netflix
    - DPI reads the TLS "Server Name Indication" (SNI) to determine
      the exact website

Techniques used:
  1. TLS SNI Extraction — Reads the domain name from HTTPS handshakes
  2. HTTP Host Header  — Reads the Host: header from HTTP requests
  3. DNS Query Parsing — Reads domain names from DNS lookups
  4. Port-based fallback — Uses well-known ports (80=HTTP, 443=HTTPS)


"""

from scapy.all import IP, TCP, UDP, DNS, Raw
from scapy.packet import Packet
from typing import Dict, Any, Optional, List, Set
from parser import get_five_tuple


# ═══════════════════════════════════════════════════════════════════
# Application Classification
# ═══════════════════════════════════════════════════════════════════

# Map of domain patterns to application names.
# If a domain contains any of these keywords, it's classified as that app.
# If a domain contains any of these keywords, it's classified as that app.
APP_SIGNATURES: Dict[str, str] = {
    "google":     "Google",
    "youtube":    "YouTube",
    "facebook":   "Facebook",
    "instagram":  "Instagram",
    "twitter":    "Twitter",
    "netflix":    "Netflix",
    "amazon":     "Amazon",
    "microsoft":  "Microsoft",
    "apple":      "Apple",
    "whatsapp":   "WhatsApp",
    "telegram":   "Telegram",
    "tiktok":     "TikTok",
    "spotify":    "Spotify",
    "zoom":       "Zoom",
    "discord":    "Discord",
    "github":     "GitHub",
    "cloudflare": "Cloudflare",
    "reddit":     "Reddit",
    "linkedin":   "LinkedIn",
    "twitch":     "Twitch",
}

# Well-known port numbers and the protocols/services they represent.
# Used as a fallback when payload-based detection doesn't work.
PORT_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class DPIEngine:
    """
    Deep Packet Inspection Engine.

    Inspects packet payload data to classify applications, track connections,
    and enforce blocking rules. Prioritizes clarity and ease of understanding.

    Usage:
        engine = DPIEngine()
        for packet in packets:
            result = engine.inspect(packet)
            print(result)
        engine.print_statistics()
    """

    def __init__(self):
        """
        Initialize the DPI engine.

        Sets up:
        - Statistics counters
        - Blocked rules (IPs, domains, apps, ports)
        - Connection tracking table
        """
        # ─── Statistics ────────────────────────────────────────────
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "other_packets": 0,
            "classified": 0,      # Successfully identified the application
            "unclassified": 0,    # Could not determine the application
            "blocked": 0,         # Packets matching a blocking rule
            "forwarded": 0,       # Packets allowed through
        }

        # ─── Application distribution ─────────────────────────────
        # Counts how many connections belong to each app
        self.app_counts: Dict[str, int] = {}

        # ─── Blocking rules ───────────────────────────────────────
        # Blocking rules for IPs, domains, apps, and ports
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.blocked_apps: Set[str] = set()
        self.blocked_ports: Set[int] = set()
        self.domain_patterns: List[str] = []  # Wildcard patterns like "*.facebook.com"

        # ─── Connection tracking ──────────────────────────────────
        # Maps 5-tuple strings to their classification results
        self.connections: Dict[str, Dict[str, Any]] = {}

    # ═══════════════════════════════════════════════════════════════
    # Core Inspection
    # ═══════════════════════════════════════════════════════════════

    def inspect(self, packet: Packet) -> Dict[str, Any]:
        """
        Inspect a single packet using Deep Packet Inspection.

        This is the main DPI function that runs the inspection pipeline.

        The inspection pipeline:
          1. Extract the 5-tuple (IPs, ports, protocol)
          2. Check if this connection was already classified
          3. If not, try to identify the application:
             a. TLS SNI extraction (for HTTPS traffic)
             b. HTTP Host header extraction (for HTTP traffic)
             c. DNS query extraction (for DNS traffic)
             d. Port-based classification (fallback)
          4. Check blocking rules
          5. Return the complete result

        Args:
            packet: A Scapy Packet object

        Returns:
            Dictionary with inspection results:
            {
                "five_tuple": {...},
                "app": "YouTube",
                "domain": "www.youtube.com",
                "protocol_type": "HTTPS",
                "action": "FORWARD" or "DROP",
                "block_reason": None or "Blocked app: YouTube"
            }
        """
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += len(packet)

        result = {
            "app": "Unknown",
            "domain": "",
            "protocol_type": "Unknown",
            "action": "FORWARD",    # Default: let the packet through
            "block_reason": None,
        }

        # Count by transport protocol
        if packet.haslayer(TCP):
            self.stats["tcp_packets"] += 1
        elif packet.haslayer(UDP):
            self.stats["udp_packets"] += 1
        else:
            self.stats["other_packets"] += 1

        # Get the 5-tuple
        five_tuple = get_five_tuple(packet)
        if not five_tuple:
            self.stats["unclassified"] += 1
            return result

        result["five_tuple"] = five_tuple

        # Create a unique key for this connection
        conn_key = self._make_conn_key(five_tuple)

        # Check if we already classified this connection with a known app
        if conn_key in self.connections and self.connections[conn_key].get("app", "Unknown") != "Unknown":
            cached = self.connections[conn_key]
            result["app"] = cached.get("app", "Unknown")
            result["domain"] = cached.get("domain", "")
            result["protocol_type"] = cached.get("protocol_type", "Unknown")
        else:
            # Try to classify this packet

            # Attempt 1: TLS SNI extraction (HTTPS traffic)
            sni = self._extract_tls_sni(packet)
            if sni:
                result["domain"] = sni
                result["protocol_type"] = "HTTPS"
                result["app"] = self._domain_to_app(sni)

            # Attempt 2: HTTP Host header
            elif self._is_http(packet):
                host = self._extract_http_host(packet)
                if host:
                    result["domain"] = host
                    result["protocol_type"] = "HTTP"
                    result["app"] = self._domain_to_app(host)
                else:
                    result["protocol_type"] = "HTTP"

            # Attempt 3: DNS query
            elif packet.haslayer(DNS):
                domain = self._extract_dns_query(packet)
                if domain:
                    result["domain"] = domain
                    result["protocol_type"] = "DNS"
                    result["app"] = self._domain_to_app(domain)

            # Attempt 4: Port-based classification (fallback)
            else:
                dst_port = five_tuple.get("dst_port", 0)
                if dst_port in PORT_SERVICES:
                    result["protocol_type"] = PORT_SERVICES[dst_port]

            # Cache the classification for future packets in this connection
            # Only cache if we found a real app, so later packets can still be inspected
            if result["app"] != "Unknown" or conn_key not in self.connections:
                self.connections[conn_key] = {
                    "app": result["app"],
                    "domain": result["domain"],
                    "protocol_type": result["protocol_type"],
                }

        # Track app distribution
        if result["app"] != "Unknown":
            self.stats["classified"] += 1
            self.app_counts[result["app"]] = self.app_counts.get(result["app"], 0) + 1
        else:
            self.stats["unclassified"] += 1

        # Check blocking rules
        block_reason = self._check_rules(packet, result)
        if block_reason:
            result["action"] = "DROP"
            result["block_reason"] = block_reason
            self.stats["blocked"] += 1
        else:
            self.stats["forwarded"] += 1

        return result

    # ═══════════════════════════════════════════════════════════════
    # Protocol Extractors
    # ═══════════════════════════════════════════════════════════════

    def _extract_tls_sni(self, packet: Packet) -> Optional[str]:
        """
        Extract the Server Name Indication (SNI) from a TLS Client Hello.

        Parses raw TLS bytes to find the SNI extension.

        How TLS SNI works:
          When your browser connects to https://www.youtube.com, it sends
          a "Client Hello" message. This message includes the domain name
          in cleartext (even though the rest of HTTPS is encrypted).
          This domain name is the SNI.

        TLS Client Hello structure:
          Byte 0:     Content Type (0x16 = Handshake)
          Bytes 1-2:  TLS Version
          Bytes 3-4:  Record Length
          Byte 5:     Handshake Type (0x01 = Client Hello)
          ...then skip through random bytes, session ID, cipher suites...
          ...until we find Extension Type 0x0000 (SNI)

        Args:
            packet: A Scapy packet that might contain a TLS Client Hello

        Returns:
            The domain name (e.g., "www.youtube.com") or None
        """
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)

        # Check for TLS handshake
        if len(payload) < 9:
            return None

        # Byte 0 must be 0x16 (TLS Handshake content type)
        if payload[0] != 0x16:
            return None

        # TLS version check (bytes 1-2)
        version = (payload[1] << 8) | payload[2]
        if version < 0x0300 or version > 0x0304:
            return None

        # Byte 5 must be 0x01 (Client Hello handshake type)
        if payload[5] != 0x01:
            return None

        # Now parse the Client Hello to find the SNI extension
        try:
            offset = 5 + 4  # Skip TLS record header + handshake header

            # Skip client version (2 bytes) + random (32 bytes)
            offset += 2 + 32

            # Skip session ID
            if offset >= len(payload):
                return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            # Skip cipher suites
            if offset + 2 > len(payload):
                return None
            cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_len

            # Skip compression methods
            if offset >= len(payload):
                return None
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len

            # Now we're at the extensions
            if offset + 2 > len(payload):
                return None
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            extensions_end = offset + extensions_len

            # Parse extensions to find SNI (type 0x0000)
            while offset + 4 <= min(extensions_end, len(payload)):
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4

                if ext_type == 0x0000:  # SNI extension
                    # SNI structure: list_len(2) + type(1) + name_len(2) + name
                    if ext_len >= 5 and offset + 5 <= len(payload):
                        sni_type = payload[offset + 2]
                        sni_len = (payload[offset + 3] << 8) | payload[offset + 4]

                        if sni_type == 0x00 and offset + 5 + sni_len <= len(payload):
                            sni = payload[offset + 5: offset + 5 + sni_len]
                            return sni.decode("ascii", errors="ignore")

                offset += ext_len

        except (IndexError, ValueError):
            pass

        return None

    def _extract_http_host(self, packet: Packet) -> Optional[str]:
        """
        Extract the Host header from an HTTP request.

        Scans the HTTP payload for the Host header line.

        HTTP requests contain a "Host:" header that tells the server which
        website the client wants. For example:
          GET /index.html HTTP/1.1
          Host: www.example.com

        Args:
            packet: A Scapy packet containing HTTP data

        Returns:
            The hostname (e.g., "www.example.com") or None
        """
        if not packet.haslayer(Raw):
            return None

        try:
            payload = bytes(packet[Raw].load).decode("ascii", errors="ignore")

            # Search for "Host:" header (case-insensitive)
            for line in payload.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                    # Remove port number if present (e.g., "example.com:8080")
                    if ":" in host:
                        host = host.split(":")[0]
                    return host
        except Exception:
            pass

        return None

    def _extract_dns_query(self, packet: Packet) -> Optional[str]:
        """
        Extract the domain name from a DNS query.

        Uses Scapy's DNS layer to read the queried domain name.

        DNS (Domain Name System) translates human-readable domain names
        (like "google.com") into IP addresses (like "142.250.80.46").
        When we see a DNS query, we know which domain the user is
        trying to reach.

        Args:
            packet: A Scapy packet with a DNS layer

        Returns:
            The queried domain name or None
        """
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]
        # Only look at queries (not responses)
        if dns.qr != 0:
            return None

        if dns.qdcount and dns.qd:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("ascii", errors="ignore")
            return qname.rstrip(".")

        return None

    def _is_http(self, packet: Packet) -> bool:
        """
        Check if a packet contains HTTP data.

        HTTP requests always start with a method like GET, POST, PUT, etc.
        Checks if the payload starts with a known HTTP method keyword.
        """
        if not packet.haslayer(Raw):
            return False

        try:
            payload = bytes(packet[Raw].load)
            methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
            return any(payload.startswith(m) for m in methods)
        except Exception:
            return False

    def _domain_to_app(self, domain: str) -> str:
        """
        Map a domain name to an application name.

        Checks the domain against known app keyword signatures.

        Example:
          "www.youtube.com"     → "YouTube"
          "api.instagram.com"   → "Instagram"
          "random-website.com"  → "Unknown"
        """
        domain_lower = domain.lower()
        for keyword, app_name in APP_SIGNATURES.items():
            if keyword in domain_lower:
                return app_name
        return "Unknown"

    # ═══════════════════════════════════════════════════════════════
    # Rule Management (Firewall Rules)
    # ═══════════════════════════════════════════════════════════════

    def block_ip(self, ip: str):
        """Block all traffic from/to an IP address."""
        self.blocked_ips.add(ip)
        print(f"[DPI] Blocked IP: {ip}")

    def unblock_ip(self, ip: str):
        """Remove an IP from the block list."""
        self.blocked_ips.discard(ip)
        print(f"[DPI] Unblocked IP: {ip}")

    def block_domain(self, domain: str):
        """
        Block traffic to a domain. Supports wildcards.
        Examples: "facebook.com" or "*.tiktok.com"
        """
        if "*" in domain:
            self.domain_patterns.append(domain)
        else:
            self.blocked_domains.add(domain.lower())
        print(f"[DPI] Blocked domain: {domain}")

    def unblock_domain(self, domain: str):
        """Remove a domain from the block list."""
        if "*" in domain:
            if domain in self.domain_patterns:
                self.domain_patterns.remove(domain)
        else:
            self.blocked_domains.discard(domain.lower())
        print(f"[DPI] Unblocked domain: {domain}")

    def block_app(self, app_name: str):
        """Block all traffic from a specific application."""
        self.blocked_apps.add(app_name)
        print(f"[DPI] Blocked app: {app_name}")

    def unblock_app(self, app_name: str):
        """Remove an app from the block list."""
        self.blocked_apps.discard(app_name)
        print(f"[DPI] Unblocked app: {app_name}")

    def block_port(self, port: int):
        """Block all traffic on a specific port."""
        self.blocked_ports.add(port)
        print(f"[DPI] Blocked port: {port}")

    def unblock_port(self, port: int):
        """Remove a port from the block list."""
        self.blocked_ports.discard(port)
        print(f"[DPI] Unblocked port: {port}")

    def _check_rules(self, packet: Packet, result: Dict) -> Optional[str]:
        """
        Check if a packet matches any blocking rule.

        Checks rules in order of priority:
          1. IP blocking (most specific)
          2. Port blocking
          3. App blocking
          4. Domain blocking

        Returns:
            A reason string if blocked, or None if allowed.
        """
        five_tuple = result.get("five_tuple")
        if not five_tuple:
            return None

        # Check IP rules
        src_ip = five_tuple.get("src_ip", "")
        dst_ip = five_tuple.get("dst_ip", "")
        if src_ip in self.blocked_ips:
            return f"Blocked IP: {src_ip}"
        if dst_ip in self.blocked_ips:
            return f"Blocked IP: {dst_ip}"

        # Check port rules
        dst_port = five_tuple.get("dst_port", 0)
        if dst_port in self.blocked_ports:
            return f"Blocked port: {dst_port}"

        # Check app rules
        app = result.get("app", "Unknown")
        if app in self.blocked_apps:
            return f"Blocked app: {app}"

        # Check domain rules
        domain = result.get("domain", "").lower()
        if domain:
            if domain in self.blocked_domains:
                return f"Blocked domain: {domain}"
            for pattern in self.domain_patterns:
                if self._domain_matches_pattern(domain, pattern):
                    return f"Blocked domain pattern: {pattern}"

        return None

    def _domain_matches_pattern(self, domain: str, pattern: str) -> bool:
        """
        Check if a domain matches a wildcard pattern.
        Example: "video.youtube.com" matches "*.youtube.com"
        """
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".youtube.com"
            if domain.endswith(suffix) or domain == pattern[2:]:
                return True
        return False

    def _make_conn_key(self, five_tuple: Dict) -> str:
        """Create a unique string key from a 5-tuple for connection tracking."""
        return (
            f"{five_tuple['src_ip']}:{five_tuple['src_port']}-"
            f"{five_tuple['dst_ip']}:{five_tuple['dst_port']}-"
            f"{five_tuple['protocol']}"
        )

    # ═══════════════════════════════════════════════════════════════
    # Statistics & Reporting
    # ═══════════════════════════════════════════════════════════════

    def print_statistics(self):
        """
        Print a comprehensive statistics report.

        Shows packet counts, classification results, and app distribution.
        """
        print("\n" + "=" * 60)
        print("              DPI ENGINE STATISTICS")
        print("=" * 60)

        print("\n  PACKET STATISTICS")
        print(f"  {'Total Packets:':<25} {self.stats['total_packets']:>10}")
        print(f"  {'Total Bytes:':<25} {self.stats['total_bytes']:>10}")
        print(f"  {'TCP Packets:':<25} {self.stats['tcp_packets']:>10}")
        print(f"  {'UDP Packets:':<25} {self.stats['udp_packets']:>10}")
        print(f"  {'Other Packets:':<25} {self.stats['other_packets']:>10}")

        print(f"\n  CLASSIFICATION RESULTS")
        print(f"  {'Classified:':<25} {self.stats['classified']:>10}")
        print(f"  {'Unclassified:':<25} {self.stats['unclassified']:>10}")

        print(f"\n  FILTERING RESULTS")
        print(f"  {'Forwarded:':<25} {self.stats['forwarded']:>10}")
        print(f"  {'Blocked:':<25} {self.stats['blocked']:>10}")

        if self.app_counts:
            print("\n  APPLICATION DISTRIBUTION")
            print(f"  {'-' * 40}")
            sorted_apps = sorted(
                self.app_counts.items(), key=lambda x: x[1], reverse=True
            )
            total = sum(c for _, c in sorted_apps)
            for app, count in sorted_apps:
                pct = (100.0 * count / total) if total > 0 else 0
                bar = "#" * int(pct / 5)
                print(f"  {app:<18} {count:>6}  {pct:5.1f}%  {bar}")

        print(f"\n  ACTIVE CONNECTIONS: {len(self.connections)}")
        print("=" * 60)

    def get_statistics(self) -> Dict[str, Any]:
        """Return statistics as a dictionary (for programmatic access)."""
        return {
            **self.stats,
            "app_distribution": dict(self.app_counts),
            "active_connections": len(self.connections),
        }
