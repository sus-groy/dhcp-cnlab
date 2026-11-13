"""
dhcp_server.py - Interactive RFC 2131 Compliant DHCP Server

Maintains an internal dynamic IP address pool, handles the complete DORA handshake,
distinguishes broadcast vs unicast traffic, gracefully handles multiple DHCP servers,
and provides live visual terminal tracking of address allocations and leases.
"""

import argparse
import sys
import time
import threading
import socket
from typing import Dict, Optional, Tuple

from dhcp_packet import (
    DHCPPacket,
    OP_BOOTREQUEST,
    OP_BOOTREPLY,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_RELEASE,
    DHCP_DECLINE,
    OPT_DHCP_MESSAGE_TYPE,
    OPT_SERVER_IDENTIFIER,
    OPT_REQUESTED_IP,
    OPT_LEASE_TIME,
    OPT_SUBNET_MASK,
    OPT_ROUTER,
    OPT_DNS_SERVERS,
    OPT_HOST_NAME,
)
from network_utils import (
    get_local_ip,
    calculate_broadcast,
    create_dhcp_socket,
    badge_broadcast,
    badge_unicast,
    badge_step,
    colorize,
    BOLD,
    DIM,
    GREEN,
    CYAN,
    YELLOW,
    RED,
    MAGENTA,
    WHITE,
    RESET,
)

# Status constants for IP addresses in pool
STATUS_AVAILABLE = "AVAILABLE"
STATUS_OFFERED = "OFFERED"
STATUS_LEASED = "LEASED"


class IPLease:
    """Tracks state and expiration for an IP address in the server pool."""
    def __init__(self, ip: str):
        self.ip = ip
        self.status = STATUS_AVAILABLE
        self.mac: Optional[str] = None
        self.hostname: Optional[str] = None
        self.expires_at: float = 0.0  # Unix timestamp
        self.offered_at: float = 0.0

    @property
    def remaining_seconds(self) -> int:
        if self.status == STATUS_AVAILABLE:
            return 0
        rem = int(self.expires_at - time.time())
        return max(0, rem)

    def is_expired(self) -> bool:
        if self.status == STATUS_OFFERED:
            # Offers expire after 30 seconds if not confirmed by REQUEST
            return (time.time() - self.offered_at) > 30.0
        elif self.status == STATUS_LEASED:
            return time.time() >= self.expires_at
        return False

    def release(self):
        """Reset IP back to available."""
        self.status = STATUS_AVAILABLE
        self.mac = None
        self.hostname = None
        self.expires_at = 0.0
        self.offered_at = 0.0


class DHCPServer:
    """
    RFC 2131 DHCP Server Implementation.
    """
    def __init__(self,
                 server_ip: str,
                 pool_start: str,
                 pool_end: str,
                 subnet_mask: str = "255.255.255.0",
                 router: Optional[str] = None,
                 dns_servers: Optional[list] = None,
                 lease_time: int = 120,
                 server_port: int = 6767,
                 client_port: int = 6868,
                 broadcast_ip: Optional[str] = None):
        self.server_ip = server_ip
        self.subnet_mask = subnet_mask
        self.router = router or server_ip
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1"]
        self.lease_time = lease_time
        self.server_port = server_port
        self.client_port = client_port
        self.broadcast_ip = broadcast_ip or calculate_broadcast(server_ip, subnet_mask)

        # Initialize IP pool
        self.pool: Dict[str, IPLease] = {}
        self._init_pool(pool_start, pool_end)

        self.running = False
        self.sock: Optional[socket.socket] = None
        self.lock = threading.RLock()

    def _init_pool(self, start_ip: str, end_ip: str):
        """Populate the pool with consecutive IPs."""
        start_parts = [int(p) for p in start_ip.split('.')]
        end_parts = [int(p) for p in end_ip.split('.')]

        base_prefix = '.'.join(str(p) for p in start_parts[:3])
        start_host = start_parts[3]
        end_host = end_parts[3]

        for host in range(start_host, end_host + 1):
            ip = f"{base_prefix}.{host}"
            self.pool[ip] = IPLease(ip)

    def print_pool_status(self):
        """Renders a clean tabular status of the IP pool."""
        with self.lock:
            total = len(self.pool)
            available = sum(1 for item in self.pool.values() if item.status == STATUS_AVAILABLE)
            offered = sum(1 for item in self.pool.values() if item.status == STATUS_OFFERED)
            leased = sum(1 for item in self.pool.values() if item.status == STATUS_LEASED)

            print(f"\n{BOLD}{CYAN}===== DHCP SERVER LEASE TABLE & POOL STATUS ====={RESET}")
            print(f"Total IPs: {total} | {GREEN}Available: {available}{RESET} | {YELLOW}Offered: {offered}{RESET} | {MAGENTA}Leased: {leased}{RESET}")
            print(f"{DIM}{'-' * 78}{RESET}")
            print(f"{BOLD}{'IP Address':<16} {'MAC Address':<20} {'Hostname':<16} {'Status':<12} {'Expires In':<12}{RESET}")
            print(f"{DIM}{'-' * 78}{RESET}")

            for ip, item in self.pool.items():
                if item.status == STATUS_LEASED:
                    status_str = colorize(f"{item.status:<12}", GREEN)
                    rem_str = f"{item.remaining_seconds}s"
                elif item.status == STATUS_OFFERED:
                    status_str = colorize(f"{item.status:<12}", YELLOW)
                    rem_str = f"{max(0, int(30 - (time.time() - item.offered_at)))}s (offer)"
                else:
                    status_str = colorize(f"{item.status:<12}", DIM)
                    rem_str = "-"

                mac_str = item.mac if item.mac else "-"
                host_str = item.hostname if item.hostname else "-"
                print(f"{ip:<16} {mac_str:<20} {host_str:<16} {status_str} {rem_str:<12}")
            print(f"{DIM}{'-' * 78}{RESET}\n")

    def _cleanup_expired_leases(self):
        """Background thread loop to reclaim expired offers and leases."""
        while self.running:
            time.sleep(2)
            with self.lock:
                for ip, item in list(self.pool.items()):
                    if item.is_expired():
                        old_status = item.status
                        old_mac = item.mac
                        item.release()
                        print(f"{colorize('[POOL CLEANUP]', RED)} {old_status} for {ip} (MAC: {old_mac}) expired and released back to pool.")

    def _find_available_ip(self, preferred_ip: Optional[str] = None, mac: Optional[str] = None) -> Optional[str]:
        """
        Locates an available IP.
        1. If client previously held a lease for an IP, prefer that IP.
        2. If preferred_ip is valid and available, use it.
        3. Otherwise pick first available IP.
        """
        if mac:
            for ip, item in self.pool.items():
                if item.mac == mac and item.status in (STATUS_AVAILABLE, STATUS_OFFERED, STATUS_LEASED):
                    return ip

        if preferred_ip and preferred_ip in self.pool:
            if self.pool[preferred_ip].status == STATUS_AVAILABLE:
                return preferred_ip

        for ip, item in self.pool.items():
            if item.status == STATUS_AVAILABLE:
                return ip

        return None

    def handle_discover(self, req: DHCPPacket, client_addr: Tuple[str, int]):
        """
        DORA Step 2: Handle DHCPDISCOVER and reply with DHCPOFFER.
        """
        print(f"\n{badge_step('DISCOVER')} {badge_broadcast()} Received DHCPDISCOVER from MAC: {colorize(req.chaddr, YELLOW)}")
        hostname = req.host_name or "Unknown"
        print(f"  Client Hostname: {hostname} | Transaction ID (xid): 0x{req.xid:08X}")

        with self.lock:
            offered_ip = self._find_available_ip(req.requested_ip, req.chaddr)
            if not offered_ip:
                print(f"  {colorize('[ERROR]', RED)} IP pool exhausted! Cannot offer IP to {req.chaddr}")
                return

            lease = self.pool[offered_ip]
            lease.status = STATUS_OFFERED
            lease.mac = req.chaddr
            lease.hostname = hostname
            lease.offered_at = time.time()

        offer = DHCPPacket(
            op=OP_BOOTREPLY,
            xid=req.xid,
            secs=0,
            flags=req.flags,
            ciaddr="0.0.0.0",
            yiaddr=offered_ip,
            siaddr=self.server_ip,
            giaddr=req.giaddr,
            chaddr=req.chaddr,
            sname="Python-DHCP-Server",
        )
        offer.message_type = DHCP_OFFER
        offer.server_identifier = self.server_ip
        offer.lease_time = self.lease_time
        offer.subnet_mask = self.subnet_mask
        offer.router = self.router
        offer.dns_servers = self.dns_servers

        packet_bytes = offer.to_bytes()
        if client_addr[0] == "127.0.0.1" or self.broadcast_ip == "127.0.0.1":
            dest_ip = "127.0.0.1"
        elif req.is_broadcast:
            dest_ip = "255.255.255.255"
        else:
            dest_ip = self.broadcast_ip
        dest_addr = (dest_ip, client_addr[1])  # <--- Use addr[1] instead of self.client_port

        self.sock.sendto(packet_bytes, dest_addr)
        print(f"{badge_step('OFFER')} {badge_broadcast()} Sent DHCPOFFER to {dest_addr[0]}:{dest_addr[1]}")
        print(f"  Offered IP: {colorize(offered_ip, GREEN)} to MAC: {req.chaddr} (Valid for {self.lease_time}s)")

    def handle_request(self, req: DHCPPacket, client_addr: Tuple[str, int]):
        """
        DORA Step 4: Handle DHCPREQUEST and reply with DHCPACK (or DHCPNAK).
        Includes handling for multiple DHCP servers on the same network!
        """
        server_id = req.server_identifier
        requested_ip = req.requested_ip or (req.ciaddr if req.ciaddr != "0.0.0.0" else None)

        print(f"\n{badge_step('REQUEST')} {badge_broadcast()} Received DHCPREQUEST from MAC: {colorize(req.chaddr, YELLOW)}")
        print(f"  Requested IP: {requested_ip} | Server Identifier in request: {server_id}")

        # MULTIPLE DHCP SERVERS HANDLING:
        # If the client sent a server identifier and it is NOT this server's IP,
        # it means the client selected ANOTHER DHCP server's offer!
        if server_id and server_id != self.server_ip:
            print(f"  {colorize('[MULTI-SERVER EVENT]', MAGENTA)} Client chose another DHCP server ({server_id}).")
            print(f"  Releasing reserved offer for MAC {req.chaddr} back to available pool.")
            with self.lock:
                for ip, item in self.pool.items():
                    if item.mac == req.chaddr and item.status == STATUS_OFFERED:
                        item.release()
            return

        with self.lock:
            valid_lease = False
            if requested_ip and requested_ip in self.pool:
                item = self.pool[requested_ip]
                if item.mac == req.chaddr or item.status in (STATUS_AVAILABLE, STATUS_OFFERED):
                    valid_lease = True

            if valid_lease and requested_ip:
                lease = self.pool[requested_ip]
                lease.status = STATUS_LEASED
                lease.mac = req.chaddr
                lease.hostname = req.host_name or lease.hostname or "Unknown"
                lease.expires_at = time.time() + self.lease_time

                ack = DHCPPacket(
                    op=OP_BOOTREPLY,
                    xid=req.xid,
                    secs=0,
                    flags=req.flags,
                    ciaddr=req.ciaddr,
                    yiaddr=requested_ip,
                    siaddr=self.server_ip,
                    giaddr=req.giaddr,
                    chaddr=req.chaddr,
                    sname="Python-DHCP-Server",
                )
                ack.message_type = DHCP_ACK
                ack.server_identifier = self.server_ip
                ack.lease_time = self.lease_time
                ack.subnet_mask = self.subnet_mask
                ack.router = self.router
                ack.dns_servers = self.dns_servers

                packet_bytes = ack.to_bytes()
                if client_addr[0] == "127.0.0.1" or self.broadcast_ip == "127.0.0.1":
                    dest_ip = "127.0.0.1"
                elif req.is_broadcast:
                    dest_ip = "255.255.255.255"
                else:
                    dest_ip = self.broadcast_ip
                dest_addr = (dest_ip, client_addr[1])  # <--- Use addr[1] instead of self.client_port

                self.sock.sendto(packet_bytes, dest_addr)
                print(f"{badge_step('ACK')} {badge_broadcast()} Sent DHCPACK to {dest_addr[0]}:{dest_addr[1]}")
                print(f"  {colorize('SUCCESS:', GREEN)} Bound IP {colorize(requested_ip, GREEN)} to MAC {req.chaddr} for {self.lease_time}s.")
                self.print_pool_status()
            else:
                print(f"  {colorize('[NAK]', RED)} Requested IP {requested_ip} is invalid or unavailable!")
                nak = DHCPPacket(
                    op=OP_BOOTREPLY,
                    xid=req.xid,
                    flags=req.flags,
                    ciaddr="0.0.0.0",
                    yiaddr="0.0.0.0",
                    siaddr=self.server_ip,
                    giaddr=req.giaddr,
                    chaddr=req.chaddr,
                )
                nak.message_type = DHCP_NAK
                nak.server_identifier = self.server_ip

                dest_ip = "127.0.0.1" if (client_addr[0] == "127.0.0.1" or self.broadcast_ip == "127.0.0.1") else "255.255.255.255"
                dest_addr = (dest_ip, client_addr[1])  # <--- Use addr[1] instead of self.client_port
                self.sock.sendto(nak.to_bytes(), dest_addr)
                print(f"{badge_step('NAK')} {badge_broadcast()} Sent DHCPNAK to MAC: {req.chaddr}")

    def handle_release(self, req: DHCPPacket, client_addr: Tuple[str, int]):
        """
        Handle DHCPRELEASE: client gives up its IP address lease.
        According to RFC 2131, this packet is UNICAST from client to server.
        """
        print(f"\n{badge_step('RELEASE')} {badge_unicast()} Received DHCPRELEASE from MAC: {req.chaddr} (IP: {req.ciaddr})")
        with self.lock:
            released = False
            for ip, item in self.pool.items():
                if item.mac == req.chaddr or (req.ciaddr != "0.0.0.0" and ip == req.ciaddr):
                    item.release()
                    released = True
                    print(f"  {colorize('RELEASED:', CYAN)} IP {ip} successfully returned to available pool.")
            if not released:
                print(f"  {colorize('[NOTE]', YELLOW)} No active lease found for MAC {req.chaddr}.")

        self.print_pool_status()

    def handle_decline(self, req: DHCPPacket, client_addr: Tuple[str, int]):
        """Handle DHCPDECLINE: client detected IP address conflict on the network."""
        print(f"\n{badge_step('DECLINE')} Received DHCPDECLINE from MAC: {req.chaddr} for IP: {req.requested_ip}")
        with self.lock:
            if req.requested_ip and req.requested_ip in self.pool:
                self.pool[req.requested_ip].release()

    def start(self):
        """Starts the DHCP server listener."""
        self.running = True
        self.sock = create_dhcp_socket(bind_port=self.server_port, bind_ip="0.0.0.0")
        self.sock.settimeout(1.0)  # <--- ADD THIS LINE: 1-second timeout

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_expired_leases, daemon=True)
        cleanup_thread.start()

        print(f"\n{BOLD}{GREEN}==================================================================={RESET}")
        print(f"{BOLD}{GREEN}                 RFC 2131 PYTHON DHCP SERVER                       {RESET}")
        print(f"{BOLD}{GREEN}==================================================================={RESET}")
        print(f" Server IP:        {colorize(self.server_ip, CYAN)}")
        print(f" Subnet Mask:      {self.subnet_mask}")
        print(f" Router (Gateway): {self.router}")
        print(f" DNS Servers:      {', '.join(self.dns_servers)}")
        print(f" Lease Time:       {self.lease_time} seconds")
        print(f" Listening Port:   {colorize(str(self.server_port), YELLOW)} (Clients listen on: {self.client_port})")
        print(f" Broadcast Target: {self.broadcast_ip}")
        print(f"{DIM}{'-' * 67}{RESET}")

        self.print_pool_status()
        print(f"{BOLD}{GREEN}Listening for DHCP packets... (Press Ctrl+C to stop){RESET}\n")

        try:
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    try:
                        packet = DHCPPacket.from_bytes(data)
                    except Exception as e:
                        print(f"{colorize('[ERROR]', RED)} Malformed packet from {addr}: {e}")
                        continue

                    msg_type = packet.message_type

                    if msg_type == DHCP_DISCOVER:
                        self.handle_discover(packet, addr)
                    elif msg_type == DHCP_REQUEST:
                        self.handle_request(packet, addr)
                    elif msg_type == DHCP_RELEASE:
                        self.handle_release(packet, addr)
                    elif msg_type == DHCP_DECLINE:
                        self.handle_decline(packet, addr)
                    else:
                        print(f"Received unhandled message type: {packet.message_type_name}")
                
                except socket.timeout:    # <--- ADD THIS EXCEPTION BLOCK
                    continue              # Wake up and check for Ctrl+C, then loop again
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")
                        time.sleep(0.5)

        except KeyboardInterrupt:
            print(f"\n{colorize('Stopping DHCP Server...', YELLOW)}")
        finally:
            self.running = False
            if self.sock:
                self.sock.close()
            print(f"{colorize('DHCP Server shut down cleanly.', GREEN)}")


def display_bootp_vs_dhcp_differences():
    """Prints a comparative table highlighting differences between BOOTP and DHCP."""
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}                    KEY DIFFERENCES: BOOTP vs. DHCP                             {RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{'Feature':<22} | {'BOOTP (RFC 951)':<24} | {'DHCP (RFC 2131)':<28}{RESET}")
    print(f"{DIM}{'-' * 80}{RESET}")
    print(f"{'Address Allocation':<22} | {'Static (Manual MAC map)':<24} | {'Dynamic, Automatic & Static':<28}")
    print(f"{'Lease Concept':<22} | {'Permanent / Indefinite':<24} | {'Dynamic with Lease Expiry':<28}")
    print(f"{'Address Reclamation':<22} | {'Cannot reclaim unused IPs':<24} | {'Automatic expiration / Release':<28}")
    print(f"{'Handshake Protocol':<22} | {'2-Way (Request/Reply)':<24} | {'4-Way DORA (Discover-Offer-Req-Ack)':<28}")
    print(f"{'Options Support':<22} | {'Fixed 64-byte Vendor Area':<24} | {'Variable TLV Options (>312 bytes)':<28}")
    print(f"{'Multi-Server Support':<22} | {'No server selection':<24} | {'Option 54 (Server Identifier)':<28}")
    print(f"{'Packet Header':<22} | {'Standard 236-byte BOOTP':<24} | {'Extends BOOTP Header + Magic Cookie':<28}")
    print(f"{DIM}{'-' * 80}{RESET}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="RFC 2131 Python DHCP Server")
    parser.add_argument("--ip", type=str, default="", help="Server IP address (default: auto-detected LAN IP)")
    parser.add_argument("--pool-start", type=str, default="", help="First IP in pool (e.g. 192.168.1.100)")
    parser.add_argument("--pool-end", type=str, default="", help="Last IP in pool (e.g. 192.168.1.110)")
    parser.add_argument("--lease-time", type=int, default=120, help="Lease time in seconds (default: 120)")
    parser.add_argument("--subnet-mask", type=str, default="255.255.255.0", help="Subnet mask")
    parser.add_argument("--gateway", type=str, default="", help="Default gateway router IP")
    parser.add_argument("--dns", type=str, default="8.8.8.8,1.1.1.1", help="Comma-separated DNS servers")
    parser.add_argument("--server-port", type=int, default=6767, help="Server port (default: 6767, or 67 for standard)")
    parser.add_argument("--client-port", type=int, default=6868, help="Client port (default: 6868, or 68 for standard)")
    parser.add_argument("--standard", action="store_true", help="Use standard DHCP ports 67 (server) and 68 (client)")
    parser.add_argument("--show-diff", action="store_true", help="Display BOOTP vs DHCP comparison table and exit")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.show_diff:
        display_bootp_vs_dhcp_differences()
        sys.exit(0)

    # Resolve ports
    s_port = 67 if args.standard else args.server_port
    c_port = 68 if args.standard else args.client_port

    # Auto-detect IP if not provided
    local_ip = args.ip or get_local_ip()
    ip_parts = local_ip.split('.')
    base_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

    pool_start = args.pool_start or f"{base_subnet}.100"
    pool_end = args.pool_end or f"{base_subnet}.110"
    gateway = args.gateway or local_ip
    dns_list = [d.strip() for d in args.dns.split(',')]

    server = DHCPServer(
        server_ip=local_ip,
        pool_start=pool_start,
        pool_end=pool_end,
        subnet_mask=args.subnet_mask,
        router=gateway,
        dns_servers=dns_list,
        lease_time=args.lease_time,
        server_port=s_port,
        client_port=c_port
    )

    # Always show comparison highlight on startup
    display_bootp_vs_dhcp_differences()

    server.start()
