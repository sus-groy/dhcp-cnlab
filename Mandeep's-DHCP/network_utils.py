"""
network_utils.py - Networking & Console Utilities for DHCP Implementation

Provides IP discovery, MAC extraction, broadcast address computation,
socket initialization, and ANSI terminal color formatting.
"""

import os
import sys
import socket
import struct
import subprocess
import uuid
from typing import Tuple, Optional

# Enable ANSI colors on Windows 10/11 cmd and PowerShell
if os.name == 'nt':
    os.system('')

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

BG_BLUE = "\033[44m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_MAGENTA = "\033[45m"


def colorize(text: str, color: str) -> str:
    """Return text wrapped in ANSI color codes."""
    return f"{color}{text}{RESET}"


def badge_broadcast() -> str:
    """Distinct badge highlighting a BROADCAST packet."""
    return f"{BOLD}{YELLOW}[BROADCAST]{RESET}"


def badge_unicast() -> str:
    """Distinct badge highlighting a UNICAST packet."""
    return f"{BOLD}{CYAN}[UNICAST]  {RESET}"


def badge_step(step_name: str) -> str:
    """Badge for DORA handshake step."""
    colors = {
        "DISCOVER": BG_YELLOW + WHITE,
        "OFFER": BG_BLUE + WHITE,
        "REQUEST": BG_MAGENTA + WHITE,
        "ACK": BG_GREEN + WHITE,
        "NAK": RED,
        "RELEASE": DIM,
    }
    bg = colors.get(step_name.upper(), BOLD)
    return f"{BOLD}{bg} [DORA: {step_name.upper()}] {RESET}"


def get_local_ip(preferred_subnet_prefix: str = "") -> str:
    """
    Detect the active local LAN or Hotspot IPv4 address.
    Attempts a dummy UDP connection to determine routing interface.
    """
    # 1. If preferred prefix given (e.g. "192.168.137."), check host addresses
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if preferred_subnet_prefix and ip.startswith(preferred_subnet_prefix):
                return ip
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                default_candidate = ip
    except Exception:
        pass

    # 2. Dummy UDP connection trick (doesn't send any traffic)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass

    # 3. Fallback
    return "127.0.0.1"


def get_mac_address() -> str:
    """
    Get the machine's primary hardware MAC address in '00:11:22:33:44:55' format.
    Uses uuid.getnode() as a reliable cross-platform mechanism.
    """
    node = uuid.getnode()
    mac = ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(40, -1, -8))
    return mac


def calculate_broadcast(ip: str, subnet_mask: str = "255.255.255.0") -> str:
    """Calculate the directed subnet broadcast address (e.g. 192.168.1.255)."""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(subnet_mask))[0]
        broadcast_int = (ip_int & mask_int) | (~mask_int & 0xFFFFFFFF)
        return socket.inet_ntoa(struct.pack("!I", broadcast_int))
    except Exception:
        return "255.255.255.255"


def create_dhcp_socket(bind_port: int,
                       bind_ip: str = "0.0.0.0",
                       allow_broadcast: bool = True,
                       reuse_addr: bool = True) -> socket.socket:
    """
    Creates and configures a UDP socket for DHCP transmission.
    Sets SO_BROADCAST and SO_REUSEADDR flags.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    if reuse_addr:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass

    if allow_broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # On Windows, SO_EXCLUSIVEADDRUSE might be set by default; SO_REUSEADDR overrides it.
    sock.bind((bind_ip, bind_port))
    return sock


def subnet_mask_to_cidr(mask: str) -> int:
    """
    Convert dotted subnet mask (e.g. '255.255.255.0') to prefix length (e.g. 24).
    """
    try:
        if not mask:
            return 24
        parts = str(mask).strip().split(".")
        if len(parts) == 4:
            return sum(bin(int(p)).count("1") for p in parts)
    except Exception:
        pass
    return 24


def detect_active_interface(target_ip: str = "8.8.8.8") -> Optional[str]:
    """
    Auto-detect the active connected interface name ('wlan0'/'eth0' on Linux via
    'ip route get', or interface alias like 'Wi-Fi' on Windows via PowerShell/netsh).
    """
    if sys.platform.startswith("linux"):
        # 1. Try 'ip route get <target_ip>'
        try:
            cmd = ["ip", "route", "get", target_ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                tokens = res.stdout.strip().split()
                if "dev" in tokens:
                    idx = tokens.index("dev")
                    if idx + 1 < len(tokens):
                        return tokens[idx + 1]
        except Exception:
            pass

        # 2. Try 'ip route show default'
        try:
            cmd = ["ip", "route", "show", "default"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                tokens = res.stdout.strip().split()
                if "dev" in tokens:
                    idx = tokens.index("dev")
                    if idx + 1 < len(tokens):
                        return tokens[idx + 1]
        except Exception:
            pass

        # 3. Fallback: Check /sys/class/net for active non-loopback interface
        try:
            if os.path.isdir("/sys/class/net"):
                candidates = []
                for iface in os.listdir("/sys/class/net"):
                    if iface == "lo" or iface.startswith(("docker", "veth", "br-")):
                        continue
                    operstate_path = f"/sys/class/net/{iface}/operstate"
                    if os.path.exists(operstate_path):
                        with open(operstate_path, "r") as f:
                            state = f.read().strip()
                            if state == "up":
                                return iface
                    candidates.append(iface)
                if candidates:
                    return candidates[0]
        except Exception:
            pass

    elif sys.platform.startswith("win"):
        # 1. Try PowerShell Find-NetRoute
        try:
            cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"(Find-NetRoute -RemoteIPAddress '{target_ip}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -First 1)"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                val = res.stdout.strip()
                if val:
                    return val.splitlines()[0].strip()
        except Exception:
            pass

        # 2. Try PowerShell Get-NetRoute for default route (0.0.0.0/0)
        try:
            cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -First 1)"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                val = res.stdout.strip()
                if val:
                    return val.splitlines()[0].strip()
        except Exception:
            pass

        # 3. Try PowerShell connected interface
        try:
            cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Sort-Object InterfaceMetric | Select-Object -ExpandProperty InterfaceAlias -First 1)"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                val = res.stdout.strip()
                if val:
                    return val.splitlines()[0].strip()
        except Exception:
            pass

        # 4. Fallback via netsh interface ipv4 show interfaces
        try:
            res = subprocess.run(["netsh", "interface", "ipv4", "show", "interfaces"],
                                 capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split(None, 4)
                    if len(parts) == 5:
                        idx, met, mtu, state, name = parts
                        if state.lower() == "connected" and "loopback" not in name.lower():
                            return name.strip()
        except Exception:
            pass

    elif sys.platform.startswith("darwin"):
        try:
            cmd = ["route", "-n", "get", target_ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "interface:" in line:
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass

    return None


def apply_secondary_ip(ip: str, subnet_mask: str, interface: str) -> bool:
    """
    Bind the leased IP as a secondary IP address (IP alias) to the network interface.
    Windows: netsh interface ipv4 add address name="<interface>" addr=<ip> mask=<subnet_mask>
    Linux: ip addr add <ip>/<cidr> broadcast + dev <interface>
    If permissions are insufficient, logs a warning and returns False gracefully.
    """
    if not ip or not interface:
        return False

    cidr = subnet_mask_to_cidr(subnet_mask)
    print(f"\n{colorize('[SECONDARY IP]', CYAN)} Binding leased IP {colorize(f'{ip}/{cidr}', YELLOW)} to interface {colorize(interface, YELLOW)}...")

    try:
        if sys.platform.startswith("win"):
            cmd = f'netsh interface ipv4 add address name="{interface}" addr={ip} mask={subnet_mask}'
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        elif sys.platform.startswith("linux"):
            cmd = ["ip", "addr", "add", f"{ip}/{cidr}", "broadcast", "+", "dev", interface]
            res = subprocess.run(cmd, capture_output=True, text=True)
        elif sys.platform.startswith("darwin"):
            cmd = ["ifconfig", interface, "alias", ip, "netmask", subnet_mask]
            res = subprocess.run(cmd, capture_output=True, text=True)
        else:
            print(f"  {colorize('[WARNING]', YELLOW)} Unsupported OS platform for network binding: {sys.platform}")
            return False

        if res.returncode == 0:
            print(f"  {colorize('[SUCCESS]', GREEN)} Bound secondary IP {colorize(f'{ip}/{cidr}', CYAN)} to interface '{interface}'.")
            return True
        else:
            err_msg = (res.stderr or res.stdout).strip()
            print(f"  {colorize('[WARNING]', YELLOW)} Could not bind secondary IP to interface '{interface}' (exit code {res.returncode}).")
            print(f"  {colorize('[HINT]', YELLOW)} Administrator / sudo privileges are required to configure network interfaces.")
            if err_msg:
                print(f"  {DIM}Details: {err_msg}{RESET}")
            return False
    except Exception as e:
        print(f"  {colorize('[WARNING]', YELLOW)} Exception while applying secondary IP: {e}")
        return False


def remove_secondary_ip(ip: str, subnet_mask: str, interface: str) -> bool:
    """
    Unbind the secondary IP address from the network interface upon release/exit.
    Windows: netsh interface ipv4 delete address name="<interface>" addr=<ip>
    Linux: ip addr del <ip>/<cidr> dev <interface>
    """
    if not ip or not interface:
        return False

    cidr = subnet_mask_to_cidr(subnet_mask)
    print(f"\n{colorize('[SECONDARY IP]', CYAN)} Unbinding secondary IP {colorize(f'{ip}/{cidr}', YELLOW)} from interface {colorize(interface, YELLOW)}...")

    try:
        if sys.platform.startswith("win"):
            cmd = f'netsh interface ipv4 delete address name="{interface}" addr={ip}'
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        elif sys.platform.startswith("linux"):
            cmd = ["ip", "addr", "del", f"{ip}/{cidr}", "dev", interface]
            res = subprocess.run(cmd, capture_output=True, text=True)
        elif sys.platform.startswith("darwin"):
            cmd = ["ifconfig", interface, "-alias", ip]
            res = subprocess.run(cmd, capture_output=True, text=True)
        else:
            return False

        if res.returncode == 0:
            print(f"  {colorize('[SUCCESS]', GREEN)} Removed secondary IP {colorize(f'{ip}/{cidr}', CYAN)} from interface '{interface}'.")
            return True
        else:
            err_msg = (res.stderr or res.stdout).strip()
            print(f"  {colorize('[WARNING]', YELLOW)} Could not remove secondary IP {ip} from interface '{interface}' (exit code {res.returncode}).")
            if err_msg:
                print(f"  {DIM}Details: {err_msg}{RESET}")
            return False
    except Exception as e:
        print(f"  {colorize('[WARNING]', YELLOW)} Exception while removing secondary IP: {e}")
        return False
