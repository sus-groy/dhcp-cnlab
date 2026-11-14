## Python DHCP Simulation: Quick Start Guide

### Prerequisites

* All laptops must have **Python 3** installed.
* No external libraries are needed (it uses standard Python modules).
* For the multi-laptop scenario, all laptops must be connected to the **same Wi-Fi network or Mobile Hotspot**.

---

### Scenario A: Running Locally (Testing on a Single Laptop)

You can simulate an entire network on one screen by opening multiple terminal windows side-by-side.

**1. Start the Server (Terminal 1)**
Navigate to the folder containing the scripts and run:

```bash
python dhcp_server.py

```

*Leave this running. It will show an empty pool of 11 IP addresses.*

**2. Connect Client 1 (Terminal 2)**
To talk to the server locally, point the broadcast to `127.0.0.1` (localhost). We will assign it a fake MAC address and a specific port:

```bash
python dhcp_client.py --broadcast 127.0.0.1 --mac 00:11:22:33:44:01 --hostname Laptop-1 --client-port 6868

```

**3. Connect Client 2 (Terminal 3)**
To run a second client at the exact same time without port conflicts, give it a different MAC, hostname, and client port:

```bash
python dhcp_client.py --broadcast 127.0.0.1 --mac 00:11:22:33:44:02 --hostname Laptop-2 --client-port 6869

```

*Watch Terminal 1: You will see the server dynamically assign two different IPs and update its live tracking table.*

---

### Scenario B: Running on Multiple Laptops (Real Network)

This is where you use physical machines. Because standard DHCP ports (67/68) require Administrator/Root privileges, this script uses non-privileged ports (6767/6868). To make this work across real Wi-Fi, the clients just need to know your network's specific Broadcast IP.

**1. Start the Server (Laptop 1)**
Run the server script normally:

```bash
python dhcp_server.py

```

*Look at the startup text in the terminal. Find the **"Broadcast Target"** (for example, it might say `192.168.1.255` or `10.0.0.255`). Write this down.*

**2. Start the Clients (Laptop 2, Laptop 3, etc.)**
On the other friends' laptops, run the client script, but replace `<TARGET>` with the **Broadcast Target** you wrote down from the server laptop.

```bash
python dhcp_client.py --broadcast <TARGET>

```

*Example: `python dhcp_client.py --broadcast 192.168.1.255*`

**Important Notes for Multi-Laptop Testing:**

* **No Extra Flags Needed:** You do *not* need to use `--mac`, `--hostname`, or `--client-port` here. The script will automatically pull their real hardware MAC addresses and computer names, and they can all safely use the default port (6868) since they are on separate physical machines.
* **Firewalls:** If the client hangs on `Sending DHCPDISCOVER...` and gets a timeout, Laptop 1 (the Server) likely has Windows Defender or Mac Firewall blocking incoming UDP traffic on port 6767. Temporarily disable the firewall on the Server laptop, or add an allow rule for Python/Port 6767.