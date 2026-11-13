"""
network_utils.py - Networking & Console Utilities for DHCP Implementation

Provides IP discovery, MAC extraction, broadcast address computation,
socket initialization, and ANSI terminal color formatting.
"""

import os
import sys
import socket
import struct
import uuid
from typing import Tuple

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
