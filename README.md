# RFC 2131 Dynamic Host Configuration Protocol (DHCP) Implementation

A Python implementation of the **Dynamic Host Configuration Protocol (DHCP)** built from scratch over standard UDP sockets. This project implements RFC 2131 and RFC 2132 packet specifications, enabling 4 laptops to form a network over a single Wi-Fi hotspot or router—where **one laptop operates as the DHCP Server** and the **other 3 laptops operate as DHCP Clients**.

---

## 🌟 Key Features & Requirements Met

| Requirement | Implementation Detail |
| :--- | :--- |
| **Strict RFC 2131/2132 Binary Format** | Full 236-byte BOOTP header + Magic Cookie (`0x63825363`) + variable TLV Options array (`struct`-packed). Wire-compatible with Wireshark. |
| **4-Laptop Hotspot Network** | 1 Server laptop manages dynamic IP leases; 3 Client laptops independently discover and bind IPs over a single Wi-Fi hotspot or router. |
| **DORA Handshake** | Complete 4-step DORA lifecycle: `DHCPDISCOVER` ➔ `DHCPOFFER` ➔ `DHCPREQUEST` ➔ `DHCPACK` (+ `DHCPRELEASE`). |
| **Broadcast vs. Unicast Display** | Explicit color-coded terminal badges (`[BROADCAST]` vs `[UNICAST]`) detailing transmission types and target addresses. |
| **Multi-DHCP-Server Handling** | Implements RFC 2131 Option 54 (`Server Identifier`). Clients evaluate multiple offers; unselected servers detect rejection and reclaim reserved IPs. |
| **Dynamic IP Pool & Live Tracking** | Live terminal lease table tracking `AVAILABLE`, `OFFERED`, and `LEASED` states with active countdown timers and background lease expiration. |
| **BOOTP vs. DHCP Comparison** | Built-in CLI comparison matrix explaining architectural differences. |

---

## 📁 Project Architecture & File Organization

```
Mandeep's DHCP/
├── dhcp_packet.py       # RFC 2131/2132 binary encoder/decoder (BOOTP header + DHCP options)
├── dhcp_server.py       # DHCP Server: pool manager, lease timers, DORA responder
├── dhcp_client.py       # DHCP Client: DORA initiator, offer selector, lease manager
├── network_utils.py     # IP discovery, MAC resolution, broadcast sockets, ANSI styling
├── demo_test.py         # Automated multi-laptop simulation & multi-server test suite
└── README.md            # Comprehensive project documentation & Wireshark guide
```

---

## 🔄 The DORA Protocol Workflow

DHCP extends BOOTP by introducing dynamic lease negotiation over a 4-way UDP exchange:

```
    Client (Laptop 2/3/4)                               DHCP Server (Laptop 1)
              |                                                   |
              | -------- 1. DHCPDISCOVER [BROADCAST] -----------> |
              |      (Who is offering IP? xid=0x12345678)         | (Reserves IP in pool as OFFERED)
              |                                                   |
              | <------- 2. DHCPOFFER [BROADCAST] --------------- |
              |      (Here is 192.168.137.100, lease=120s)        |
              |                                                   |
              | -------- 3. DHCPREQUEST [BROADCAST] ------------> |
              |      (I accept 192.168.137.100 from Server A)     | (Commits lease: marks LEASED)
              |                                                   | (Other servers revoke offers)
              | <------- 4. DHCPACK [BROADCAST] ----------------- |
              |      (Confirmed! Subnet, Router, DNS attached)    |
              |                                                   |
       [Lease Active]                                      [Lease Active]
              |                                                   |
              | -------- 5. DHCPRELEASE [UNICAST] --------------> | (Optional on shutdown)
              |      (Surrendering IP 192.168.137.100)            | (Reclaims IP to AVAILABLE)
```

### 🛰️ Broadcast vs. Unicast Breakdown
* **`DHCPDISCOVER` [BROADCAST]:** Sent by client to `255.255.255.255:67` because the client has no assigned IP address yet (`ciaddr = 0.0.0.0`).
* **`DHCPOFFER` [BROADCAST / DIRECTED]:** Broadcast by server to `255.255.255.255:68` with the client's hardware MAC address in `chaddr` and offered IP in `yiaddr`.
* **`DHCPREQUEST` [BROADCAST]:** Broadcast by client so that **all** DHCP servers on the subnet receive it. The chosen server commits the lease; competing servers see they were not chosen and release their reservations.
* **`DHCPACK` [BROADCAST / UNICAST]:** Confirms the final IP allocation and parameters.
* **`DHCPRELEASE` [UNICAST]:** Sent directly to the server's specific IP address when the client gracefully disconnects.

---

## 📊 DHCP vs. BOOTP: Core Architectural Differences

Run `python dhcp_server.py --show-diff` to view this in your terminal:

| Feature | BOOTP (RFC 951) | DHCP (RFC 2131 / 2132) |
| :--- | :--- | :--- |
| **Address Allocation** | Static only (Administrator must pre-map MAC to IP). | Dynamic pool allocation, automatic reuse, and static reservations. |
| **Lease Mechanism** | Permanent / Indefinite (No expiration time). | Dynamic with configurable lease times (`Option 51`), T1 renew, T2 rebind. |
| **Reclamation** | Cannot reclaim unused addresses automatically. | Expired or released addresses return to the available pool. |
| **Handshake** | 2-Way: `BOOTREQUEST` ➔ `BOOTREPLY`. | 4-Way DORA: `DISCOVER` ➔ `OFFER` ➔ `REQUEST` ➔ `ACK`. |
| **Options Field** | Fixed 64-byte vendor-specific extension area. | Variable-length TLV (Type-Length-Value) sequence (>312 bytes). |
| **Multiple Servers** | No server selection mechanism. | Client uses `Option 54` (`Server Identifier`) to choose one server. |
| **Packet Header** | Fixed 236-byte BOOTP header. | Reuses 236-byte BOOTP header + Magic Cookie (`0x63825363`) + TLV options. |

---

## 🌐 4-Laptop Wi-Fi Hotspot Setup Guide

To demonstrate 4 laptops communicating over a single Wi-Fi hotspot:

### Step 1: Hotspot & LAN Setup
1. On **Laptop 1** (or a smartphone), turn on the **Mobile Hotspot**.
   * Example Hotspot SSID: `Group_DHCP_Net`
2. Connect **all 4 laptops** to this Wi-Fi hotspot.
3. Check Laptop 1's Wi-Fi IP address:
   * **Windows:** Open PowerShell and run `ipconfig`. Look for the Wi-Fi IPv4 address (e.g., `192.168.137.1` or `192.168.1.15`).
   * **macOS/Linux:** Run `ifconfig` or `ip addr show`.

### Step 2: Firewall Configuration
To allow UDP broadcast packets between the laptops:
* **Windows:**
  1. Open Windows Defender Firewall with Advanced Security.
  2. Add an **Inbound Rule** allowing **UDP Ports 6767 and 6868** (or ports 67 and 68 if using standard ports).
  3. Alternatively, temporarily set the Wi-Fi network profile to *Private*.
* **macOS / Linux:**
  ```bash
  sudo ufw allow 6767/udp
  sudo ufw allow 6868/udp
  ```

---

## 🚀 Running the System

### Port Strategy: Unprivileged Ports vs. Standard Ports
* **Default (Port 6767 / 6868):** Recommended for zero-permission student demonstrations. Bypasses Windows `svchost.exe` / OS DHCP Client port conflicts and avoids requiring administrator/`sudo` privileges.
* **Standard Ports (Port 67 / 68):** Use the `--standard` flag (run PowerShell as Administrator or `sudo python`).

---

### Step 3: Start DHCP Server (Laptop 1)

```bash
# Auto-detects local LAN IP and creates a 10-IP dynamic pool:
python dhcp_server.py

# Optional customizations:
python dhcp_server.py --pool-start 192.168.137.100 --pool-end 192.168.137.110 --lease-time 180

# To run on standard ports 67/68 (requires Admin/sudo):
python dhcp_server.py --standard
```

**Server Output Sample:**
```
===================================================================
                 RFC 2131 PYTHON DHCP SERVER                       
===================================================================
 Server IP:        192.168.137.1
 Subnet Mask:      255.255.255.0
 Router (Gateway): 192.168.137.1
 DNS Servers:      8.8.8.8, 1.1.1.1
 Lease Time:       180 seconds
 Listening Port:   6767 (Clients listen on: 6868)
 Broadcast Target: 192.168.137.255
-------------------------------------------------------------------

===== DHCP SERVER LEASE TABLE & POOL STATUS =====
Total IPs: 11 | Available: 11 | Offered: 0 | Leased: 0
------------------------------------------------------------------------------
IP Address       MAC Address          Hostname         Status       Expires In  
------------------------------------------------------------------------------
192.168.137.100  -                    -                AVAILABLE    -           
192.168.137.101  -                    -                AVAILABLE    -           
...
------------------------------------------------------------------------------
Listening for DHCP packets... (Press Ctrl+C to stop)
```

---

### Step 4: Start DHCP Clients (Laptops 2, 3, 4)

Run the client script on each client laptop:

> [!TIP]
> **For Ping Commands to Work:** Run the client with **Administrator (Windows)** or **`sudo` (Linux/macOS)** privileges. The client will automatically bind the assigned IP as a secondary IP alias to the network interface, allowing direct ICMP pinging!

**Laptop 2:**
```bash
# On Linux/macOS (with sudo for ping support):
sudo python3 dhcp_client.py --hostname Laptop-2

# On Windows (open PowerShell as Administrator):
python dhcp_client.py --hostname Laptop-2
```

**Laptop 3:**
```bash
# On Linux/macOS:
sudo python3 dhcp_client.py --hostname Laptop-3

# On Windows (PowerShell as Admin):
python dhcp_client.py --hostname Laptop-3
```

**Laptop 4:**
```bash
# On Linux/macOS:
sudo python3 dhcp_client.py --hostname Laptop-4

# On Windows (PowerShell as Admin):
python dhcp_client.py --hostname Laptop-4
```

*(If running with standard ports on the server, add `--standard` to client commands).*

**Client Output Sample:**
```
--- Initializing DHCP Client (Laptop-2) ---
Hardware MAC Address: 3c:6a:9d:14:2b:8f
Network Interface:    wlan0
Connecting via UDP: Server Port=6767, Client Port=6868

 [DORA: DISCOVER]  [BROADCAST] Sending DHCPDISCOVER to 255.255.255.255:6767
  Client MAC: 3c:6a:9d:14:2b:8f | Hostname: Laptop-2 | xid: 0x4B3A8912
  Listening for DHCPOFFER responses (timeout: 6.0s)...
 [DORA: OFFER]  [BROADCAST] Received DHCPOFFER from Server 192.168.137.1
  Offered IP: 192.168.137.100 | Subnet: 255.255.255.0 | Lease: 180s

 [DORA: REQUEST]  [BROADCAST] Sending DHCPREQUEST to 255.255.255.255:6767
  Requesting IP: 192.168.137.100 from Chosen Server: 192.168.137.1

 [DORA: ACK]  [BROADCAST] Received DHCPACK from Server 192.168.137.1

===================================================================
               DHCP LEASE SUCCESSFULLY ACQUIRED!                   
===================================================================
  Assigned IPv4 Address: 192.168.137.100
  Subnet Mask:          255.255.255.0
  Default Gateway:      192.168.137.1
  DNS Servers:          8.8.8.8, 1.1.1.1
  DHCP Server ID:       192.168.137.1
  Lease Duration:       180 seconds
  Client Hardware MAC:  3c:6a:9d:14:2b:8f
  Client Hostname:      Laptop-2
===================================================================

[SECONDARY IP] Binding leased IP 192.168.137.100/24 to interface wlan0...
  [SUCCESS] Bound secondary IP 192.168.137.100/24 to interface 'wlan0'.

Press Ctrl+C at any time to release IP and disconnect from network.
```

---

### Step 5: Verify Connectivity with Ping

Once the IP lease is acquired and bound to the interface, test communication between the devices:

1. **Ping the DHCP Server (Laptop 1) from Client (Laptop 2):**
   ```bash
   ping 192.168.137.1
   ```
2. **Ping Client to Client (e.g. Laptop 2 pinging Laptop 3):**
   ```bash
   ping 192.168.137.101
   ```
3. **Ping from Server to Client:**
   ```bash
   ping 192.168.137.100
   ```

> [!IMPORTANT]
> **Firewall ICMP Setting:** If pings timeout despite being on the same hotspot, ensure ICMP Echo Requests (ping) are allowed:
> * **Windows:** Run in Admin PowerShell:
>   ```powershell
>   netsh advfirewall firewall add rule name="Allow ICMPv4" dir=in action=allow protocol=icmpv4:8,any
>   ```
> * **Linux:** ICMP is enabled by default. If using `ufw`: `sudo ufw allow icmp` or temporarily disable firewall (`sudo ufw disable`).

---

### Step 6: Test Client Disconnect (DHCPRELEASE)
Press `Ctrl+C` in any client terminal. The client will automatically remove the secondary IP alias from the OS and transmit a unicast `DHCPRELEASE` packet to Laptop 1:
```
User requested disconnection. Surrendering lease...

[SECONDARY IP] Unbinding secondary IP 192.168.137.100/24 to interface wlan0...
  [SUCCESS] Removed secondary IP 192.168.137.100/24 from interface 'wlan0'.

 [DORA: RELEASE]  [UNICAST]   Sending DHCPRELEASE to Server 192.168.137.1:6767
  Surrendering leased IP: 192.168.137.100 (MAC: 3c:6a:9d:14:2b:8f)
  IP successfully released back to server.
Client shut down cleanly.
```
Laptop 1's terminal will instantly update its lease table, returning the IP to `AVAILABLE` status for other clients!

---

## 🦈 Wireshark Packet Inspection Guide

Because our implementation builds genuine RFC 2131 binary packets, Wireshark natively dissectors every field, header, and option.

### Capturing Packets in Wireshark:
1. Open **Wireshark** and select your active **Wi-Fi adapter**.
2. **If using standard ports (67 / 68):**
   * Filter: `bootp` or `dhcp`
3. **If using default custom ports (6767 / 6868):**
   * Apply display filter: `udp.port == 6767 || udp.port == 6868`
   * Right-click on any captured packet ➔ Select **Decode As...**
   * Under the **Current** column for UDP Port `6767` and `6868`, change to **BOOTP/DHCP** ➔ Click **Save**.
4. Wireshark will now decode every packet as native DHCP!

### What to Observe in the Wireshark Packet Dissector:
* **Frame Layer:** Destination MAC `ff:ff:ff:ff:ff:ff` (Broadcast) vs client unicast MAC.
* **IP Layer:** Source `0.0.0.0` / Destination `255.255.255.255` for Discovery.
* **Bootstrap Protocol:**
  * `Message type: Boot Request (1)` or `Boot Reply (2)`
  * `Hardware type: Ethernet (0x01)`
  * `Hardware address length: 6`
  * `Transaction ID: 0x...` (matches throughout DORA exchange)
  * `Client MAC address: [client's MAC]`
* **Magic Cookie:** `DHCP` (`0x63825363`)
* **Option 53 (DHCP Message Type):** `Discover (1)`, `Offer (2)`, `Request (3)`, `ACK (5)`
* **Option 54 (Server Identifier):** IP of the responding DHCP server
* **Option 51 (IP Address Lease Time):** Lease duration in seconds
* **Option 1 (Subnet Mask):** e.g., `255.255.255.0`
* **Option 3 (Router):** Default Gateway IP
* **Option 6 (Domain Name Server):** DNS IP list

---

## 🧪 Automated Test Suite (`demo_test.py`)

A comprehensive verification test script is included to validate the entire multi-laptop flow in an automated loop:

```bash
python demo_test.py
```

### Tests Performed:
1. **RFC 2131 Packet Serialization & Deserialization:** Binary packing/unpacking roundtrip, verifying all 236 BOOTP bytes, Magic Cookie, and TLV options.
2. **4-Laptop Multi-Client Simulation:**
   * Starts DHCP Server.
   * Simulates Laptop-2, Laptop-3, and Laptop-4 joining consecutively.
   * Verifies that each laptop receives a **unique, non-overlapping IP address** from the pool.
   * Verifies real-time lease table tracking.
3. **Graceful Disconnection (DHCPRELEASE):** Laptop-3 sends unicast release; verifies that the server reclaims `192.168.10.101` back to `AVAILABLE`.
4. **Multiple DHCP Servers Handling:**
   * Starts server and offers an IP.
   * Simulates client broadcasting a `DHCPREQUEST` choosing a competing server (`Option 54 != Server IP`).
   * Verifies that the server detects rejection and immediately revokes its temporary reservation.

---

## 👥 Group Project Submission Notes
* **Topic:** Protocol B — DHCP (Dynamic Host Configuration Protocol).
* **Layer:** Application/Transport Layer Socket Programming (UDP).
* **Dependencies:** Standard Python 3.8+ Standard Library (`socket`, `struct`, `threading`, `time`, `uuid`, `argparse`). **No external `pip` dependencies required.**
