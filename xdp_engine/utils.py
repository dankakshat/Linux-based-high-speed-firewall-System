"""Networking, IP validation, and host guardrail utilities."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import socket
import struct
import subprocess
import sys

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def ip_to_u32(ip: str) -> int:
    """Convert an IPv4 string into a network-byte-order uint32."""
    packed = socket.inet_aton(ip)
    return struct.unpack("!I", packed)[0]


def u32_to_ip(val: int) -> str:
    """Convert a network-byte-order uint32 into an IPv4 string."""
    return socket.inet_ntoa(struct.pack("!I", val & 0xFFFFFFFF))


def discover_local_guardrail_ips() -> set[str]:
    """Discover loopback, interface, and default gateway IPs to avoid self-lockout."""
    safe_ips: set[str] = {"127.0.0.1", "::1"}

    if psutil is not None:
        try:
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.family in (socket.AF_INET, socket.AF_INET6):
                        clean = addr.address.split("%")[0]
                        if is_valid_ip(clean):
                            safe_ips.add(clean)
        except OSError:
            pass

    if sys.platform.startswith("linux"):
        try:
            proc_route = Path("/proc/net/route")
            if proc_route.exists():
                for line in proc_route.read_text(encoding="utf-8").splitlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        gw_hex = int(fields[2], 16)
                        gw_ip = socket.inet_ntoa(struct.pack("<I", gw_hex))
                        safe_ips.add(gw_ip)
        except OSError:
            pass
    elif sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and is_valid_ip(parts[2]):
                    safe_ips.add(parts[2])
        except (OSError, subprocess.SubprocessError):
            pass

    return safe_ips


def load_ip_list_file(path: str | Path) -> list[str]:
    """Load non-comment valid IPs from a line-delimited text file."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    ips: list[str] = []
    for raw in file_path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and is_valid_ip(line):
            ips.append(line)
    return ips
