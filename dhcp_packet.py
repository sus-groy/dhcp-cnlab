"""
dhcp_packet.py - RFC 2131 / RFC 2132 Compliant DHCP & BOOTP Packet Implementation

Structures, encodes, and decodes binary DHCP/BOOTP packets using Python's struct module.
Packets conform exactly to standard wire formats so they can be inspected in Wireshark.
"""

import struct
import socket
from typing import Dict, List, Optional, Tuple, Union

# Magic cookie identifying DHCP in BOOTP options field (RFC 1497 / RFC 2131)
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# BOOTP opcodes
OP_BOOTREQUEST = 1
OP_BOOTREPLY = 2

# DHCP Message Types (Option 53)
DHCP_MESSAGE_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
}

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

# Standard DHCP Option Codes (RFC 2132)
OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS_SERVERS = 6
OPT_HOST_NAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST_ADDRESS = 28
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_DHCP_MESSAGE_TYPE = 53
OPT_SERVER_IDENTIFIER = 54
OPT_PARAMETER_REQUEST_LIST = 55
OPT_RENEWAL_TIME_T1 = 58
OPT_REBINDING_TIME_T2 = 59
OPT_CLIENT_IDENTIFIER = 61
OPT_END = 255

OPTION_NAMES = {
    1: "Subnet Mask",
    3: "Router (Gateway)",
    6: "Domain Name Server (DNS)",
    12: "Host Name",
    15: "Domain Name",
    28: "Broadcast Address",
    50: "Requested IP Address",
    51: "IP Address Lease Time",
    53: "DHCP Message Type",
    54: "Server Identifier",
    55: "Parameter Request List",
    58: "Renewal Time Value (T1)",
    59: "Rebinding Time Value (T2)",
    61: "Client Identifier",
}


def mac_str_to_bytes(mac: str) -> bytes:
    """Convert '00:11:22:33:44:55' or '00-11-22-33-44-55' to 6 bytes."""
    clean = mac.replace(':', '').replace('-', '')
    return bytes.fromhex(clean)


def mac_bytes_to_str(mac_bytes: bytes) -> str:
    """Convert 6 bytes to '00:11:22:33:44:55' string."""
    return ':'.join(f'{b:02x}' for b in mac_bytes[:6])


def ip_str_to_bytes(ip: str) -> bytes:
    """Convert '192.168.1.1' to 4 bytes."""
    return socket.inet_aton(ip)


def ip_bytes_to_str(ip_bytes: bytes) -> str:
    """Convert 4 bytes to '192.168.1.1' string."""
    return socket.inet_ntoa(ip_bytes)


class DHCPPacket:
    """
    Represents an RFC 2131 / RFC 2132 DHCP packet.

    Format:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
     +---------------+---------------+---------------+---------------+
     |                            xid (4)                            |
     +-------------------------------+-------------------------------+
     |           secs (2)            |           flags (2)           |
     +-------------------------------+-------------------------------+
     |                          ciaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          yiaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          siaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          giaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          chaddr  (16)                         |
     +-------------------------------+-------------------------------+
     |                          sname   (64)                         |
     +-------------------------------+-------------------------------+
     |                          file    (128)                        |
     +-------------------------------+-------------------------------+
     |                          options (variable)                   |
     +-------------------------------+-------------------------------+
    """

    # BOOTP Header format string:
    # B: op (1)
    # B: htype (1)
    # B: hlen (1)
    # B: hops (1)
    # I: xid (4)
    # H: secs (2)
    # H: flags (2)
    # 4s: ciaddr (4)
    # 4s: yiaddr (4)
    # 4s: siaddr (4)
    # 4s: giaddr (4)
    # 16s: chaddr (16)
    # 64s: sname (64)
    # 128s: file (128)
    BOOTP_HEADER_FORMAT = "!BBBBIHH4s4s4s4s16s64s128s"
    BOOTP_HEADER_LEN = struct.calcsize(BOOTP_HEADER_FORMAT)  # 236 bytes

    def __init__(self,
                 op: int = OP_BOOTREQUEST,
                 htype: int = 1,  # 10Mb Ethernet
                 hlen: int = 6,   # Ethernet MAC length
                 hops: int = 0,
                 xid: int = 0,
                 secs: int = 0,
                 flags: int = 0x8000,  # 0x8000 = Broadcast flag set
                 ciaddr: str = "0.0.0.0",
                 yiaddr: str = "0.0.0.0",
                 siaddr: str = "0.0.0.0",
                 giaddr: str = "0.0.0.0",
                 chaddr: str = "00:00:00:00:00:00",
                 sname: str = "",
                 file: str = ""):
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = xid
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.file = file
        self.options: Dict[int, bytes] = {}

    @property
    def is_broadcast(self) -> bool:
        """True if the broadcast flag (0x8000) is set."""
        return bool(self.flags & 0x8000)

    @property
    def message_type(self) -> Optional[int]:
        """Returns the DHCP message type int (e.g. 1=DISCOVER, 2=OFFER)."""
        val = self.options.get(OPT_DHCP_MESSAGE_TYPE)
        return val[0] if val else None

    @message_type.setter
    def message_type(self, msg_type: int):
        self.options[OPT_DHCP_MESSAGE_TYPE] = bytes([msg_type])

    @property
    def message_type_name(self) -> str:
        """Returns friendly name like 'DHCPDISCOVER' or 'BOOTP'."""
        m_type = self.message_type
        if m_type is not None:
            return DHCP_MESSAGE_TYPES.get(m_type, f"UNKNOWN({m_type})")
        return "BOOTREQUEST" if self.op == OP_BOOTREQUEST else "BOOTREPLY"

    @property
    def server_identifier(self) -> Optional[str]:
        val = self.options.get(OPT_SERVER_IDENTIFIER)
        return ip_bytes_to_str(val) if val and len(val) == 4 else None

    @server_identifier.setter
    def server_identifier(self, ip: str):
        self.options[OPT_SERVER_IDENTIFIER] = ip_str_to_bytes(ip)

    @property
    def requested_ip(self) -> Optional[str]:
        val = self.options.get(OPT_REQUESTED_IP)
        return ip_bytes_to_str(val) if val and len(val) == 4 else None

    @requested_ip.setter
    def requested_ip(self, ip: str):
        self.options[OPT_REQUESTED_IP] = ip_str_to_bytes(ip)

    @property
    def lease_time(self) -> Optional[int]:
        val = self.options.get(OPT_LEASE_TIME)
        return struct.unpack("!I", val)[0] if val and len(val) == 4 else None

    @lease_time.setter
    def lease_time(self, seconds: int):
        self.options[OPT_LEASE_TIME] = struct.pack("!I", seconds)

    @property
    def subnet_mask(self) -> Optional[str]:
        val = self.options.get(OPT_SUBNET_MASK)
        return ip_bytes_to_str(val) if val and len(val) == 4 else None

    @subnet_mask.setter
    def subnet_mask(self, mask: str):
        self.options[OPT_SUBNET_MASK] = ip_str_to_bytes(mask)

    @property
    def router(self) -> Optional[str]:
        val = self.options.get(OPT_ROUTER)
        return ip_bytes_to_str(val[:4]) if val and len(val) >= 4 else None

    @router.setter
    def router(self, ip: str):
        self.options[OPT_ROUTER] = ip_str_to_bytes(ip)

    @property
    def dns_servers(self) -> List[str]:
        val = self.options.get(OPT_DNS_SERVERS)
        if not val or len(val) % 4 != 0:
            return []
        return [ip_bytes_to_str(val[i:i+4]) for i in range(0, len(val), 4)]

    @dns_servers.setter
    def dns_servers(self, ips: List[str]):
        self.options[OPT_DNS_SERVERS] = b''.join(ip_str_to_bytes(ip) for ip in ips)

    @property
    def host_name(self) -> Optional[str]:
        val = self.options.get(OPT_HOST_NAME)
        return val.decode("utf-8", errors="replace") if val else None

    @host_name.setter
    def host_name(self, name: str):
        self.options[OPT_HOST_NAME] = name.encode("utf-8")

    def set_parameter_request_list(self, codes: List[int]):
        self.options[OPT_PARAMETER_REQUEST_LIST] = bytes(codes)

    def to_bytes(self) -> bytes:
        """
        Serializes the DHCP packet to RFC 2131 wire format.
        Appends magic cookie and all TLV options, ending with 0xFF (OPT_END).
        Pads to at least 300 bytes (standard DHCP datagram minimum).
        """
        chaddr_bytes = mac_str_to_bytes(self.chaddr)
        # Pad chaddr to 16 bytes
        chaddr_padded = chaddr_bytes + b'\x00' * (16 - len(chaddr_bytes))

        sname_bytes = self.sname.encode("utf-8")[:63]
        sname_padded = sname_bytes + b'\x00' * (64 - len(sname_bytes))

        file_bytes = self.file.encode("utf-8")[:127]
        file_padded = file_bytes + b'\x00' * (128 - len(file_bytes))

        header = struct.pack(
            self.BOOTP_HEADER_FORMAT,
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            ip_str_to_bytes(self.ciaddr),
            ip_str_to_bytes(self.yiaddr),
            ip_str_to_bytes(self.siaddr),
            ip_str_to_bytes(self.giaddr),
            chaddr_padded,
            sname_padded,
            file_padded
        )

        options_payload = bytearray(DHCP_MAGIC_COOKIE)

        # Append options in TLV format (ordered logically)
        # Message type first if present
        ordered_codes = sorted(self.options.keys(), key=lambda c: 0 if c == OPT_DHCP_MESSAGE_TYPE else c)
        for code in ordered_codes:
            if code in (OPT_PAD, OPT_END):
                continue
            val = self.options[code]
            options_payload.append(code)
            options_payload.append(len(val))
            options_payload.extend(val)

        # End option
        options_payload.append(OPT_END)

        packet = header + bytes(options_payload)

        # Minimum BOOTP packet size is 300 bytes according to RFC
        if len(packet) < 300:
            packet += b'\x00' * (300 - len(packet))

        return packet

    @classmethod
    def from_bytes(cls, data: bytes) -> "DHCPPacket":
        """
        Parses raw binary bytes received from UDP socket into a DHCPPacket.
        Raises ValueError if packet is malformed or shorter than header length.
        """
        if len(data) < cls.BOOTP_HEADER_LEN:
            raise ValueError(f"Packet too short ({len(data)} bytes, expected at least {cls.BOOTP_HEADER_LEN})")

        header_bytes = data[:cls.BOOTP_HEADER_LEN]
        (op, htype, hlen, hops, xid, secs, flags,
         ciaddr_raw, yiaddr_raw, siaddr_raw, giaddr_raw,
         chaddr_raw, sname_raw, file_raw) = struct.unpack(cls.BOOTP_HEADER_FORMAT, header_bytes)

        # Format addresses
        ciaddr = ip_bytes_to_str(ciaddr_raw)
        yiaddr = ip_bytes_to_str(yiaddr_raw)
        siaddr = ip_bytes_to_str(siaddr_raw)
        giaddr = ip_bytes_to_str(giaddr_raw)
        chaddr = mac_bytes_to_str(chaddr_raw[:hlen])
        sname = sname_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")
        file = file_raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace")

        packet = cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            chaddr=chaddr,
            sname=sname,
            file=file
        )

        # Parse options
        remainder = data[cls.BOOTP_HEADER_LEN:]
        if len(remainder) >= 4 and remainder[:4] == DHCP_MAGIC_COOKIE:
            # DHCP mode
            idx = 4
            while idx < len(remainder):
                opt_code = remainder[idx]
                if opt_code == OPT_PAD:
                    idx += 1
                    continue
                if opt_code == OPT_END:
                    break
                if idx + 1 >= len(remainder):
                    break
                opt_len = remainder[idx + 1]
                idx += 2
                if idx + opt_len > len(remainder):
                    break
                opt_val = remainder[idx:idx + opt_len]
                packet.options[opt_code] = opt_val
                idx += opt_len

        return packet

    def format_details(self) -> str:
        """Provides a formatted summary string of the packet fields and options."""
        lines = [
            f"  Opcode:           {self.op} ({'BOOTREQUEST' if self.op == 1 else 'BOOTREPLY'})",
            f"  Message Type:     {self.message_type_name} (Option 53 = {self.message_type})",
            f"  Transaction ID:   0x{self.xid:08X}",
            f"  Flags:            0x{self.flags:04X} ({'BROADCAST' if self.is_broadcast else 'UNICAST'})",
            f"  Client MAC:       {self.chaddr}",
            f"  Client IP (ci):   {self.ciaddr}",
            f"  'Your' IP (yi):   {self.yiaddr}",
            f"  Next Svr IP (si): {self.siaddr}",
            f"  Relay IP (gi):    {self.giaddr}",
        ]
        if self.options:
            lines.append("  DHCP Options:")
            for code, raw_val in self.options.items():
                name = OPTION_NAMES.get(code, f"Option {code}")
                # Format value nicely
                if code == OPT_DHCP_MESSAGE_TYPE:
                    val_str = f"{raw_val[0]} ({DHCP_MESSAGE_TYPES.get(raw_val[0], 'Unknown')})"
                elif code in (OPT_SUBNET_MASK, OPT_ROUTER, OPT_REQUESTED_IP, OPT_SERVER_IDENTIFIER):
                    val_str = ip_bytes_to_str(raw_val) if len(raw_val) == 4 else raw_val.hex()
                elif code == OPT_DNS_SERVERS:
                    val_str = ', '.join(ip_bytes_to_str(raw_val[i:i+4]) for i in range(0, len(raw_val), 4))
                elif code in (OPT_LEASE_TIME, OPT_RENEWAL_TIME_T1, OPT_REBINDING_TIME_T2):
                    sec = struct.unpack("!I", raw_val)[0] if len(raw_val) == 4 else 0
                    val_str = f"{sec} seconds"
                elif code == OPT_HOST_NAME:
                    val_str = raw_val.decode("utf-8", errors="replace")
                elif code == OPT_PARAMETER_REQUEST_LIST:
                    val_str = f"[{', '.join(str(c) for c in raw_val)}]"
                else:
                    val_str = raw_val.hex()
                lines.append(f"    - [{code:2d}] {name:28s}: {val_str}")
        return "\n".join(lines)
