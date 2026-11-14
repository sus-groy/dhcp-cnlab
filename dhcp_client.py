"""
dhcp_client.py - Interactive RFC 2131 Compliant DHCP Client

Simulates a laptop joining a Wi-Fi / LAN network. Executes the complete DORA handshake,
demonstrates broadcast vs unicast communication, discovers offers from multiple servers,
maintains the acquired lease, and sends DHCPRELEASE upon exit.
"""

import argparse
import os
import random
import socket
import sys
import time
from typing import Optional, List, Tuple

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
    OPT_DHCP_MESSAGE_TYPE,
    OPT_SERVER_IDENTIFIER,
    OPT_REQUESTED_IP,
    OPT_LEASE_TIME,
    OPT_SUBNET_MASK,
    OPT_ROUTER,
    OPT_DNS_SERVERS,
    OPT_HOST_NAME,
    OPT_PARAMETER_REQUEST_LIST,
)
from network_utils import (
    get_mac_address,
    calculate_broadcast,
    get_local_ip,
    create_dhcp_socket,
    subnet_mask_to_cidr,
    detect_active_interface,
    apply_secondary_ip,
    remove_secondary_ip,
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


class DHCPClient:
    """
    RFC 2131 Compliant DHCP Client.
    """
    def __init__(self,
                 mac_address: Optional[str] = None,
                 hostname: Optional[str] = None,
                 server_port: int = 6767,
                 client_port: int = 6868,
                 broadcast_target: str = "255.255.255.255",
                 timeout: float = 6.0,
                 interface: Optional[str] = None):
        self.mac = mac_address or get_mac_address()
        self.hostname = hostname or socket.gethostname()
        self.server_port = server_port
        self.client_port = client_port
        self.broadcast_target = broadcast_target
        self.timeout = timeout
        self.interface = interface or detect_active_interface()
        self.ip_bound = False

        # Active lease parameters
        self.assigned_ip: Optional[str] = None
        self.server_ip: Optional[str] = None
        self.subnet_mask: Optional[str] = None
        self.router: Optional[str] = None
        self.dns_servers: List[str] = []
        self.lease_time: int = 0
        self.lease_start: float = 0.0

        self.sock: Optional[socket.socket] = None
        self.xid: int = 0

    def _init_socket(self):
        """Bind client socket to receive broadcasts on client_port."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = create_dhcp_socket(bind_port=self.client_port, bind_ip="0.0.0.0")
        self.sock.settimeout(self.timeout)

    def send_discover(self) -> int:
        """
        DORA Step 1: Send DHCPDISCOVER (BROADCAST).
        """
        self.xid = random.randint(1, 0xFFFFFFFF)

        discover = DHCPPacket(
            op=OP_BOOTREQUEST,
            xid=self.xid,
            secs=0,
            flags=0x8000,  # Broadcast flag
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=self.mac,
        )
        discover.message_type = DHCP_DISCOVER
        discover.host_name = self.hostname
        discover.set_parameter_request_list([
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVERS,
            OPT_LEASE_TIME,
            OPT_SERVER_IDENTIFIER
        ])

        payload = discover.to_bytes()
        dest = (self.broadcast_target, self.server_port)

        print(f"\n{badge_step('DISCOVER')} {badge_broadcast()} Sending DHCPDISCOVER to {dest[0]}:{dest[1]}")
        print(f"  Client MAC: {colorize(self.mac, YELLOW)} | Hostname: {self.hostname} | xid: 0x{self.xid:08X}")
        self.sock.sendto(payload, dest)
        return self.xid

    def wait_for_offers(self, wait_window: float = 2.0) -> List[Tuple[DHCPPacket, str]]:
        """
        DORA Step 2: Listen for DHCPOFFERs.
        Waits for a small window to collect responses from multiple DHCP servers if present.
        """
        print(f"  Listening for DHCPOFFER responses (timeout: {self.timeout}s)...")
        offers: List[Tuple[DHCPPacket, str]] = []
        start_time = time.time()

        while (time.time() - start_time) < wait_window or len(offers) == 0:
            remaining = self.timeout - (time.time() - start_time)
            if remaining <= 0:
                break
            self.sock.settimeout(max(0.5, remaining))
            try:
                data, addr = self.sock.recvfrom(4096)
                packet = DHCPPacket.from_bytes(data)

                # Match transaction ID and offer message type
                if packet.xid == self.xid and packet.message_type == DHCP_OFFER:
                    server_ident = packet.server_identifier or addr[0]
                    offers.append((packet, server_ident))
                    print(f"{badge_step('OFFER')} {badge_broadcast()} Received DHCPOFFER from Server {colorize(server_ident, CYAN)}")
                    print(f"  Offered IP: {colorize(packet.yiaddr, GREEN)} | Subnet: {packet.subnet_mask} | Lease: {packet.lease_time}s")
            except socket.timeout:
                if offers:
                    break  # Got at least one offer
                else:
                    break

        return offers

    def send_request(self, offered_ip: str, server_id: str):
        """
        DORA Step 3: Send DHCPREQUEST (BROADCAST).
        Broadcasts request so that:
        - The chosen server knows to send DHCPACK.
        - Other unchosen DHCP servers know their offers were rejected.
        """
        request = DHCPPacket(
            op=OP_BOOTREQUEST,
            xid=self.xid,
            secs=0,
            flags=0x8000,  # Broadcast flag
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=self.mac,
        )
        request.message_type = DHCP_REQUEST
        request.host_name = self.hostname
        request.requested_ip = offered_ip
        request.server_identifier = server_id
        request.set_parameter_request_list([
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVERS,
            OPT_LEASE_TIME,
        ])

        payload = request.to_bytes()
        dest = (self.broadcast_target, self.server_port)

        print(f"\n{badge_step('REQUEST')} {badge_broadcast()} Sending DHCPREQUEST to {dest[0]}:{dest[1]}")
        print(f"  Requesting IP: {colorize(offered_ip, GREEN)} from Chosen Server: {colorize(server_id, CYAN)}")
        if self.broadcast_target in ("255.255.255.255", "127.255.255.255"):
            print(f"  {DIM}(Broadcasting notifies other DHCP servers on LAN that their offers were declined){RESET}")
        self.sock.sendto(payload, dest)

    def wait_for_ack(self) -> bool:
        """
        DORA Step 4: Receive DHCPACK from the server.
        """
        self.sock.settimeout(self.timeout)
        start_time = time.time()

        while (time.time() - start_time) < self.timeout:
            try:
                data, addr = self.sock.recvfrom(4096)
                packet = DHCPPacket.from_bytes(data)

                if packet.xid == self.xid:
                    if packet.message_type == DHCP_ACK:
                        self.assigned_ip = packet.yiaddr
                        self.server_ip = packet.server_identifier or addr[0]
                        self.subnet_mask = packet.subnet_mask or "255.255.255.0"
                        self.router = packet.router or self.server_ip
                        self.dns_servers = packet.dns_servers or ["8.8.8.8"]
                        self.lease_time = packet.lease_time or 120
                        self.lease_start = time.time()

                        print(f"\n{badge_step('ACK')} {badge_broadcast()} Received DHCPACK from Server {colorize(self.server_ip, CYAN)}")
                        self._print_lease_success()
                        return True

                    elif packet.message_type == DHCP_NAK:
                        print(f"\n{badge_step('NAK')} {badge_broadcast()} Received DHCPNAK from Server! Request denied.")
                        return False
            except socket.timeout:
                break

        print(f"\n{colorize('[ERROR]', RED)} Timeout waiting for DHCPACK from server.")
        return False

    def send_release(self):
        """
        Send DHCPRELEASE (UNICAST) to the DHCP server when client exits.
        """
        if not self.assigned_ip or not self.server_ip:
            return

        release = DHCPPacket(
            op=OP_BOOTREQUEST,
            xid=random.randint(1, 0xFFFFFFFF),
            flags=0x0000,  # Unicast flag
            ciaddr=self.assigned_ip,
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=self.mac,
        )
        release.message_type = DHCP_RELEASE
        release.server_identifier = self.server_ip

        payload = release.to_bytes()
        dest = (self.server_ip, self.server_port)

        print(f"\n{badge_step('RELEASE')} {badge_unicast()} Sending DHCPRELEASE to Server {dest[0]}:{dest[1]}")
        print(f"  Surrendering leased IP: {colorize(self.assigned_ip, CYAN)} (MAC: {self.mac})")
        try:
            self.sock.sendto(payload, dest)
            print(f"  {colorize('IP successfully released back to server.', GREEN)}")
        except Exception as e:
            print(f"  Failed to send release: {e}")

    def _print_lease_success(self):
        """Display summary card of acquired IP lease."""
        print(f"\n{BOLD}{GREEN}==================================================================={RESET}")
        print(f"{BOLD}{GREEN}               DHCP LEASE SUCCESSFULLY ACQUIRED!                   {RESET}")
        print(f"{BOLD}{GREEN}==================================================================={RESET}")
        print(f"  Assigned IPv4 Address: {BOLD}{CYAN}{self.assigned_ip}{RESET}")
        print(f"  Subnet Mask:          {self.subnet_mask}")
        print(f"  Default Gateway:      {self.router}")
        print(f"  DNS Servers:          {', '.join(self.dns_servers)}")
        print(f"  DHCP Server ID:       {self.server_ip}")
        print(f"  Lease Duration:       {self.lease_time} seconds")
        print(f"  Client Hardware MAC:  {self.mac}")
        print(f"  Client Hostname:      {self.hostname}")
        print(f"{BOLD}{GREEN}==================================================================={RESET}\n")

    def run(self):
        """Executes full DORA handshake and maintains lease."""
        print(f"\n{BOLD}{CYAN}--- Initializing DHCP Client ({self.hostname}) ---{RESET}")
        print(f"Hardware MAC Address: {colorize(self.mac, YELLOW)}")
        if self.interface:
            print(f"Network Interface:    {colorize(self.interface, CYAN)}")
        print(f"Connecting via UDP: Server Port={self.server_port}, Client Port={self.client_port}")

        self._init_socket()

        # Step 1: Send DISCOVER
        self.send_discover()

        # Step 2: Collect DHCPOFFERs (Handles multiple DHCP servers)
        offers = self.wait_for_offers()
        if not offers:
            print(f"{colorize('[ERROR]', RED)} No DHCPOFFER received! Check if DHCP Server is running.")
            return False

        if len(offers) > 1:
            print(f"\n{colorize('[MULTI-SERVER DETECTED]', MAGENTA)} Received {len(offers)} offers from different servers:")
            for i, (off, s_id) in enumerate(offers, 1):
                print(f"  [{i}] Server {s_id} offered IP {off.yiaddr}")
            print(f"  Selecting first offer from Server {offers[0][1]}...")

        selected_offer, selected_server_id = offers[0]
        offered_ip = selected_offer.yiaddr

        # Step 3: Send REQUEST
        self.send_request(offered_ip=offered_ip, server_id=selected_server_id)

        # Step 4: Wait for ACK
        if not self.wait_for_ack():
            return False

        if self.interface:
            self.ip_bound = apply_secondary_ip(self.assigned_ip, self.subnet_mask, self.interface)

        # Maintain lease loop until Ctrl+C
        print(f"{DIM}Press Ctrl+C at any time to release IP and disconnect from network.{RESET}")
        try:
            while True:
                time.sleep(1)
                elapsed = time.time() - self.lease_start
                remaining = int(self.lease_time - elapsed)
                if remaining <= 0:
                    print(f"\n{colorize('[LEASE EXPIRED]', RED)} IP lease has expired.")
                    break
        except KeyboardInterrupt:
            print(f"\n{colorize('User requested disconnection. Surrendering lease...', YELLOW)}")
        finally:
            if self.ip_bound and self.interface:
                try:
                    remove_secondary_ip(self.assigned_ip, self.subnet_mask, self.interface)
                except Exception as e:
                    print(f"  Failed to remove secondary IP: {e}")
                self.ip_bound = False
            self.send_release()
            if self.sock:
                self.sock.close()
            print(f"{colorize('Client shut down cleanly.', GREEN)}")
        return True


def parse_args():
    parser = argparse.ArgumentParser(description="RFC 2131 Python DHCP Client")
    parser.add_argument("--hostname", type=str, default="", help="Client hostname (e.g. Laptop-2)")
    parser.add_argument("--mac", type=str, default="", help="Client MAC address (e.g. 00:11:22:33:44:55)")
    parser.add_argument("--interface", "-i", type=str, default="", help="Physical network adapter name, e.g. 'Wi-Fi' or 'wlan0'")
    parser.add_argument("--server-port", type=int, default=6767, help="Server port (default: 6767, or 67 for standard)")
    parser.add_argument("--client-port", type=int, default=6868, help="Client port (default: 6868, or 68 for standard)")
    parser.add_argument("--standard", action="store_true", help="Use standard DHCP ports 67 (server) and 68 (client)")
    parser.add_argument("--broadcast", type=str, default="", help="Broadcast destination IP (default: 255.255.255.255)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    s_port = 67 if args.standard else args.server_port
    c_port = 68 if args.standard else args.client_port

    bcast = args.broadcast or "255.255.255.255"

    client = DHCPClient(
        mac_address=args.mac or None,
        hostname=args.hostname or None,
        server_port=s_port,
        client_port=c_port,
        broadcast_target=bcast,
        interface=args.interface or None
    )
    client.run()
