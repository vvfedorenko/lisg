"""Pure-Python ARP request sender — no external binaries required.

Uses AF_PACKET raw sockets (requires CAP_NET_RAW / root, same as ISGd).
Interface resolution is done via /proc/net/route (longest-prefix match).
MAC and IP of the local interface are read via SIOCGIFHWADDR / SIOCGIFADDR.
"""
from __future__ import annotations

import fcntl
import socket
import struct
import time

_ETH_P_ARP   = 0x0806
_ARP_REQUEST = 1
_ARP_REPLY   = 2
_SIOCGIFADDR   = 0x8915
_SIOCGIFHWADDR = 0x8927


# ── routing / interface helpers ───────────────────────────────────────────────

def _route_iface(dst_ip: str) -> str:
    """Return the outgoing interface for dst_ip, only for directly-connected subnets.

    Skips routes with a non-zero gateway — those go through a router and ARP
    cannot reach the target across an L3 boundary.  Raises OSError if the only
    matching route is via a gateway (or no route exists at all).
    """
    target = struct.unpack('<I', socket.inet_aton(dst_ip))[0]
    best_prefix = -1
    best_iface  = ''
    with open('/proc/net/route') as f:
        next(f)
        for line in f:
            parts = line.split()
            if len(parts) < 8:
                continue
            gateway = int(parts[2], 16)
            if gateway != 0:            # routed — not L2-reachable
                continue
            dest = int(parts[1], 16)
            mask = int(parts[7], 16)
            if (target & mask) == dest:
                prefix_len = bin(mask).count('1')
                if prefix_len > best_prefix:
                    best_prefix = prefix_len
                    best_iface  = parts[0]
    if not best_iface:
        raise OSError(f'{dst_ip} is not on a directly connected subnet')
    return best_iface


def _iface_mac(iface: str) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        buf = fcntl.ioctl(s.fileno(), _SIOCGIFHWADDR,
                          struct.pack('256s', iface[:15].encode()))
    return buf[18:24]


def _iface_ip(iface: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        buf = fcntl.ioctl(s.fileno(), _SIOCGIFADDR,
                          struct.pack('256s', iface[:15].encode()))
    return socket.inet_ntoa(buf[20:24])


# ── ARP frame builder ─────────────────────────────────────────────────────────

def _build_arp_request(src_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    eth = (
        b'\xff\xff\xff\xff\xff\xff'          # dst: broadcast
        + src_mac                            # src
        + struct.pack('!H', _ETH_P_ARP)      # EtherType
    )
    arp = struct.pack(
        '!HHBBH6s4s6s4s',
        1,                                   # hw type: Ethernet
        0x0800,                              # proto: IPv4
        6, 4,                                # hw / proto addr sizes
        _ARP_REQUEST,
        src_mac, socket.inet_aton(src_ip),
        b'\x00' * 6, socket.inet_aton(dst_ip),
    )
    return eth + arp


# ── main blocking call (run via asyncio.to_thread) ────────────────────────────

def arping_sync(ip: str, count: int = 3, timeout: float = 2.0) -> dict:
    iface   = _route_iface(ip)
    src_mac = _iface_mac(iface)
    src_ip  = _iface_ip(iface)
    frame   = _build_arp_request(src_mac, src_ip, ip)
    dst_ip_bytes = socket.inet_aton(ip)

    rtts: list[float] = []
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(_ETH_P_ARP))
    try:
        sock.bind((iface, 0))
        for _ in range(count):
            t0 = time.monotonic()
            sock.send(frame)
            deadline = t0 + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    data = sock.recv(60)
                except TimeoutError:
                    break
                # ARP reply: EtherType at [12:14], opcode at [20:22], sender IP at [28:32]
                if (len(data) >= 42
                        and data[12:14] == struct.pack('!H', _ETH_P_ARP)
                        and struct.unpack('!H', data[20:22])[0] == _ARP_REPLY
                        and data[28:32] == dst_ip_bytes):
                    rtts.append(round((time.monotonic() - t0) * 1000, 3))
                    break
    finally:
        sock.close()

    return {
        'ip':               ip,
        'iface':            iface,
        'reachable':        bool(rtts),
        'packets_sent':     count,
        'packets_received': len(rtts),
        'rtt_ms':           rtts,
        'avg_rtt_ms':       round(sum(rtts) / len(rtts), 3) if rtts else None,
    }
