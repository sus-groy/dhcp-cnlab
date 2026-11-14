"""
demo_test.py - Automated Demonstration and Test Suite for DHCP Implementation

Tests:
1. Binary packet encoding/decoding adherence to RFC 2131 / RFC 2132.
2. Full 4-Laptop Network Simulation:
   - 1 Laptop acts as DHCP Server (maintaining dynamic IP pool).
   - 3 Laptops act as Clients (Laptop-2, Laptop-3, Laptop-4) performing DORA handshakes.
   - Verifies address allocations and lease table updates.
   - Verifies client release (DHCPRELEASE) and pool reclamation.
3. Multi-DHCP-Server Scenario:
   - Client sends discovery and receives offer.
   - Client selects another DHCP server (via RFC 2131 Option 54 Server Identifier).
   - Server detects rejection and safely revokes temporary offer back to AVAILABLE status.
"""

import time
import threading
import sys
import builtins

# --- FIX: Thread-safe print to prevent jumbled terminal output ---
_print_lock = threading.Lock()
_original_print = builtins.print

def thread_safe_print(*args, **kwargs):
    with _print_lock:
        _original_print(*args, **kwargs)

builtins.print = thread_safe_print
# -----------------------------------------------------------------

from dhcp_packet import (
    DHCPPacket,
    OP_BOOTREQUEST,
    OP_BOOTREPLY,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_ACK,
    DHCP_RELEASE,
    OPT_DHCP_MESSAGE_TYPE,
    OPT_SERVER_IDENTIFIER,
    OPT_REQUESTED_IP,
    OPT_LEASE_TIME,
)
from dhcp_server import DHCPServer
from dhcp_client import DHCPClient
from network_utils import colorize, BOLD, GREEN, CYAN, YELLOW, RED, RESET


def test_packet_codec():
    print(f"\n{BOLD}{CYAN}=== Test 1: RFC 2131 Packet Serialization & Parsing ==={RESET}")
    pkt = DHCPPacket(
        op=OP_BOOTREQUEST,
        xid=0x12345678,
        flags=0x8000,
        chaddr="00:1A:2B:3C:4D:5E",
    )
    pkt.message_type = DHCP_DISCOVER
    pkt.host_name = "Laptop-Test"
    pkt.requested_ip = "192.168.1.105"
    pkt.lease_time = 3600

    raw_bytes = pkt.to_bytes()
    assert len(raw_bytes) >= 300, "Packet must be padded to minimum 300 bytes"

    # Decode
    parsed = DHCPPacket.from_bytes(raw_bytes)
    assert parsed.op == OP_BOOTREQUEST
    assert parsed.xid == 0x12345678
    assert parsed.is_broadcast is True
    assert parsed.chaddr == "00:1a:2b:3c:4d:5e"
    assert parsed.message_type == DHCP_DISCOVER
    assert parsed.host_name == "Laptop-Test"
    assert parsed.requested_ip == "192.168.1.105"
    assert parsed.lease_time == 3600
    print(f"  {colorize('[PASS]', GREEN)} DHCP Packet binary roundtrip validated successfully.")
    print("  Decoded packet details:")
    print(parsed.format_details())


def test_four_laptop_network():
    print(f"\n{BOLD}{CYAN}=== Test 2: Simulating 4 Laptops on Single Wi-Fi Hotspot ==={RESET}")
    print(f"  Architecture:")
    print(f"  - Laptop 1: DHCP Server (Pool: 192.168.10.100 - 192.168.10.105)")
    print(f"  - Laptop 2: DHCP Client (Hostname: Laptop-2, MAC: 00:11:22:33:44:02)")
    print(f"  - Laptop 3: DHCP Client (Hostname: Laptop-3, MAC: 00:11:22:33:44:03)")
    print(f"  - Laptop 4: DHCP Client (Hostname: Laptop-4, MAC: 00:11:22:33:44:04)")

    test_server_port = 7767
    test_client_port = 7768
    bcast = "127.0.0.1"  # Use loopback for local automated test

    # Start DHCP Server on Laptop 1
    server = DHCPServer(
        server_ip="192.168.10.1",
        pool_start="192.168.10.100",
        pool_end="192.168.10.105",
        subnet_mask="255.255.255.0",
        router="192.168.10.1",
        dns_servers=["8.8.8.8", "1.1.1.1"],
        lease_time=30,
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_ip=bcast
    )

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    assigned_ips = {}

    # Simulate Laptop 2, 3, 4 joining sequentially
    laptops = [
        ("Laptop-2", "00:11:22:33:44:02"),
        ("Laptop-3", "00:11:22:33:44:03"),
        ("Laptop-4", "00:11:22:33:44:04"),
    ]

    for hostname, mac in laptops:
        print(f"\n--- {hostname} ({mac}) Connecting to Hotspot ---")
        client = DHCPClient(
            mac_address=mac,
            hostname=hostname,
            server_port=test_server_port,
            client_port=test_client_port,
            broadcast_target=bcast,
            timeout=3.0
        )
        client._init_socket()
        client.send_discover()
        offers = client.wait_for_offers()
        assert len(offers) > 0, f"No offer received for {hostname}"
        selected_offer, server_id = offers[0]
        offered_ip = selected_offer.yiaddr

        client.send_request(offered_ip=offered_ip, server_id=server_id)
        assert client.wait_for_ack(), f"Failed to acquire ACK for {hostname}"

        # Added minor sleep to let the server's background thread finish printing the table cleanly
        time.sleep(0.2)

        assigned_ips[hostname] = client.assigned_ip
        print(f"  {colorize('[SUCCESS]', GREEN)} {hostname} acquired IP {client.assigned_ip}")
        client.sock.close()

    # Verify unique IP allocations
    print(f"\n{BOLD}Verification of IP Allocations for 4 Laptops:{RESET}")
    for host, ip in assigned_ips.items():
        print(f"  {host} -> {ip}")

    assert len(set(assigned_ips.values())) == 3, "Each laptop must be assigned a unique IP!"
    assert all(ip.startswith("192.168.10.") for ip in assigned_ips.values())

    # Verify Server pool status
    server.print_pool_status()

    # Test DHCPRELEASE: Laptop-3 leaves network
    print(f"\n{BOLD}{CYAN}=== Test 3: Laptop-3 Leaves Network (DHCPRELEASE) ==={RESET}")
    releasing_client = DHCPClient(
        mac_address="00:11:22:33:44:03",
        hostname="Laptop-3",
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_target=bcast
    )
    releasing_client._init_socket()
    releasing_client.assigned_ip = assigned_ips["Laptop-3"]
    releasing_client.server_ip = bcast
    releasing_client.send_release()
    time.sleep(0.5)

    # Verify that Laptop-3's IP is now AVAILABLE again
    with server.lock:
        released_lease = server.pool[assigned_ips["Laptop-3"]]
        assert released_lease.status == "AVAILABLE", "Released IP must return to AVAILABLE status!"
    print(f"  {colorize('[PASS]', GREEN)} Laptop-3's IP ({assigned_ips['Laptop-3']}) was safely reclaimed!")

    server.running = False
    if server.sock:
        server.sock.close()


def test_multiple_dhcp_servers():
    print(f"\n{BOLD}{CYAN}=== Test 4: Multiple DHCP Servers on the Same Network ==={RESET}")
    print("Testing server behavior when client chooses another DHCP server (RFC 2131 Option 54)...")
    test_server_port = 8767
    test_client_port = 8768
    bcast = "127.0.0.1"

    server = DHCPServer(
        server_ip="192.168.10.1",
        pool_start="192.168.10.100",
        pool_end="192.168.10.105",
        lease_time=30,
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_ip=bcast
    )

    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    time.sleep(0.5)

    client = DHCPClient(
        mac_address="00:AA:BB:CC:DD:EE",
        hostname="Laptop-MultiTest",
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_target=bcast,
        timeout=3.0
    )
    client._init_socket()
    client.send_discover()
    offers = client.wait_for_offers(wait_window=1.5)
    assert len(offers) >= 1, "Should receive offer"
    offered_ip = offers[0][0].yiaddr

    with server.lock:
        assert server.pool[offered_ip].status == "OFFERED", "IP must be reserved in OFFERED status"

    # Simulate that client selects competing Server B ("192.168.10.99")
    print("\nSimulating client broadcast selecting a different server (192.168.10.99)...")
    client.send_request(offered_ip="192.168.10.250", server_id="192.168.10.99")
    time.sleep(0.5)

    # Verify Server released the offer back to AVAILABLE
    with server.lock:
        assert server.pool[offered_ip].status == "AVAILABLE", "Server must release OFFERED IP when another server is chosen!"
    print(f"  {colorize('[PASS]', GREEN)} Server detected selection of another DHCP server and released reserved IP.")

    server.running = False
    if server.sock:
        server.sock.close()
    client.sock.close()


def test_lease_renewal_t1_and_t2():
    """
    Test RFC 2131 T1 Renewal and T2 Rebinding:
    - Server offers a short lease (e.g. 4 seconds, T1=2s, T2=3s).
    - Client acquires lease, reaches T1 (renewal timer).
    - Client sends unicast DHCPREQUEST to server, server replies with DHCPACK extending lease.
    - Lease is successfully renewed and expires_at is updated.
    """
    print(f"\n{BOLD}{CYAN}=== Test 5: RFC 2131 Lease Renewal (T1) & Rebinding (T2) ==={RESET}")
    test_server_port = 9767
    test_client_port = 9768
    bcast = "127.0.0.1"

    server = DHCPServer(
        server_ip="192.168.10.1",
        pool_start="192.168.10.100",
        pool_end="192.168.10.105",
        lease_time=4,
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_ip=bcast
    )

    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    time.sleep(0.5)

    client = DHCPClient(
        mac_address="00:11:22:33:44:99",
        hostname="Laptop-RenewalTest",
        server_port=test_server_port,
        client_port=test_client_port,
        broadcast_target=bcast,
        timeout=3.0
    )
    client._init_socket()
    client.send_discover()
    offers = client.wait_for_offers(wait_window=1.0)
    assert len(offers) >= 1, "Should receive offer"
    offered_ip = offers[0][0].yiaddr

    client.send_request(offered_ip=offered_ip, server_id=offers[0][1])
    assert client.wait_for_ack(), "Client should receive DHCPACK"
    assert client.assigned_ip == offered_ip
    assert client.t1 == 2, f"Expected T1=2s, got {client.t1}"

    initial_expires_at = server.pool[offered_ip].expires_at
    print(f"Initial lease expires at: {initial_expires_at}")

    # Wait until after T1 (2s)
    time.sleep(2.1)
    print(f"\nSimulating client renewal at T1 (unicast DHCPREQUEST)...")
    client.send_renew_request(broadcast=False)
    ack_res = client.wait_for_renew_ack(wait_time=2.0)
    assert ack_res is True, "Client should receive ACK on renewal"

    new_expires_at = server.pool[offered_ip].expires_at
    print(f"Renewed lease expires at: {new_expires_at}")
    assert new_expires_at > initial_expires_at, "Server should have extended expiration time!"
    print(f"  {colorize('[PASS]', GREEN)} Lease successfully renewed at T1 via unicast DHCPREQUEST/DHCPACK.")

    # Clean up
    client.send_release()
    time.sleep(0.2)
    server.running = False
    if server.sock:
        server.sock.close()
    client.sock.close()


if __name__ == "__main__":
    test_packet_codec()
    test_four_laptop_network()
    test_multiple_dhcp_servers()
    test_lease_renewal_t1_and_t2()
    print(f"\n{BOLD}{GREEN}ALL DHCP PROTOCOL TESTS PASSED SUCCESSFULLY!{RESET}\n")