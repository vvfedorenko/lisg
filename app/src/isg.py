"""ISG netlink protocol — constants, struct pack/unpack, socket API."""
from __future__ import annotations
import os
import re
import socket
import struct

AF_NETLINK       = socket.AF_NETLINK
ISG_NETLINK_MAIN = 31
NL_HDR_LEN       = 16
NLMSG_ALIGNTO    = 4
NLMSG_DONE       = 0x3
IN_EVENT_MSG_LEN = 184

# Events: userspace → kernel
EVENT_LISTENER_REG    = 0x01
EVENT_LISTENER_REG_V1 = 0x101
EVENT_LISTENER_UNREG  = 0x02
EVENT_SESS_APPROVE    = 0x04
EVENT_SESS_CHANGE     = 0x05
EVENT_SESS_CLEAR      = 0x09
EVENT_SESS_GETLIST    = 0x10
EVENT_SESS_GETCOUNT   = 0x12
EVENT_NE_ADD_QUEUE    = 0x14
EVENT_NE_SWEEP_QUEUE  = 0x15
EVENT_NE_COMMIT       = 0x16
EVENT_SERV_APPLY      = 0x17
EVENT_SDESC_ADD       = 0x18
EVENT_SDESC_SWEEP_TC  = 0x19
EVENT_SERV_GETLIST    = 0x20
EVENT_SESS_GETTOTALS  = 0x21

# Events: kernel → userspace
EVENT_SESS_CREATE = 0x03
EVENT_SESS_START  = 0x06
EVENT_SESS_UPDATE = 0x07
EVENT_SESS_STOP   = 0x08
EVENT_SESS_INFO   = 0x11
EVENT_SESS_COUNT  = 0x13
EVENT_SESS_TOTALS = 0x22
EVENT_KERNEL_ACK  = 0x98
EVENT_KERNEL_NACK = 0x99

# Session flags (isg_service_flags enum bit positions)
IS_APPROVED_SESSION = (1 << 0)
IS_SERVICE          = (1 << 1)
SERVICE_STATUS_ON   = (1 << 2)
SERVICE_ONLINE      = (1 << 3)
NO_ACCT             = (1 << 4)
IS_DYING            = (1 << 5)
SERVICE_TAGGER      = (1 << 6)

FLAG_OP_SET   = 0x01
FLAG_OP_UNSET = 0x02

SERVICE_DESC_IS_DYNAMIC = (1 << 0)


# ─── address / conversion helpers ────────────────────────────────────────────

def ip2long(ip: str) -> int:
    return struct.unpack('>I', socket.inet_aton(ip))[0]


def long2ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack('>I', n))


def ntohl(val: int) -> int:
    """Byte-swap a 32-bit integer (network → host on little-endian x86)."""
    return socket.ntohl(val & 0xFFFFFFFF)


def format_mac(mac_hex: str, step: int = 4) -> str:
    """Format 12-char hex MAC into dot-separated groups (Cisco style)."""
    return '.'.join(mac_hex[i:i+step] for i in range(0, 12, step))


def get_nas_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ''


def session_id_to_bytes(session_id: str) -> bytes:
    """Convert 16-char hex session ID to little-endian 8-byte binary."""
    if not re.match(r'^[0-9A-Fa-f]{16}$', session_id):
        return b'\x00' * 8
    high = int(session_id[0:8], 16)
    low  = int(session_id[8:16], 16)
    return struct.pack('=II', low, high)


# ─── netlink framing ──────────────────────────────────────────────────────────

def _align(n: int) -> int:
    return (n + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)


def _pack_nlmsg(payload: bytes, portid: int) -> bytes:
    total = _align(NL_HDR_LEN + len(payload))
    return struct.pack('=IHHII', total, 0, 0, 0, portid) + payload


def _unpack_nlmsghdr(data: bytes) -> tuple:
    return struct.unpack('=IHHII', data[:NL_HDR_LEN])


# ─── ISG event serialisation ──────────────────────────────────────────────────

def _blank() -> dict:
    return {
        'type': 0,
        'session_id': b'\x00' * 8,
        'cookie': b'',
        'ipaddr': 0, 'nat_ipaddr': 0,
        'port_number': 0,
        'flags': 0, 'flags_op': 0,
        'alive_interval': 0, 'idle_timeout': 0, 'max_duration': 0,
        'in_rate': 0, 'in_burst': 0, 'out_rate': 0, 'out_burst': 0,
        'service_name': b'',
    }


def _pad(val, length: int) -> bytes:
    if isinstance(val, int):
        val = b'\x00' * length if val == 0 else str(val).encode()
    elif isinstance(val, str):
        val = val.encode()
    return (val + b'\x00' * length)[:length]


def pack_event(ev: dict) -> bytes:
    t = ev.get('type', 0)

    if t == EVENT_SDESC_ADD:
        return (struct.pack('=I', t) + b'\x00' * 4
                + _pad(ev.get('nehash_tc_name', b''), 32)
                + _pad(ev.get('service_name', b''), 32)
                + struct.pack('=B', ev.get('service_flags', 0))
                + b'\x00' * 7)

    if t == EVENT_NE_ADD_QUEUE:
        return (struct.pack('=I', t) + b'\x00' * 4
                + struct.pack('>II', ev.get('nehash_pfx', 0), ev.get('nehash_mask', 0))
                + _pad(ev.get('nehash_tc_name', b''), 32))

    # default: isg_session_info_in (144 bytes)
    return (
        struct.pack('=I', t) + b'\x00' * 4
        + _pad(ev.get('session_id', b''), 8)
        + _pad(ev.get('cookie', b''), 32)
        + struct.pack('>II', ev.get('ipaddr', 0), ev.get('nat_ipaddr', 0))
        + b'\x00' * 8
        + struct.pack('<I', ev.get('flags', 0)) + b'\x00' * 4
        + struct.pack('=8I',
            ev.get('port_number', 0), ev.get('alive_interval', 0),
            ev.get('idle_timeout', 0), ev.get('max_duration', 0),
            ev.get('in_rate', 0), ev.get('in_burst', 0),
            ev.get('out_rate', 0), ev.get('out_burst', 0))
        + _pad(ev.get('service_name', b''), 32)
        + struct.pack('=B', ev.get('flags_op', 0)) + b'\x00' * 7
    )


def unpack_event(data: bytes) -> dict:
    """Parse isg_out_event payload (184 bytes, NL header already stripped)."""
    if len(data) < IN_EVENT_MSG_LEN:
        raise ValueError(f'ISG event payload too short: {len(data)}')

    o = 0
    ev_type, = struct.unpack_from('=I', data, o); o += 8  # +4 pad

    sid_w0, sid_w1 = struct.unpack_from('=II', data, o); o += 8
    session_id = f'{sid_w1:08X}{sid_w0:08X}'

    cookie = data[o:o+32].rstrip(b'\x00').decode('utf-8', errors='replace') or None; o += 32
    ipaddr, nat_ipaddr = struct.unpack_from('>II', data, o); o += 8
    macaddr = data[o:o+6].hex(); o += 8  # 6 mac + 2 pad

    flags, = struct.unpack_from('<I', data, o); o += 8  # 4 flags + 4 unused

    (port_number, alive_interval, idle_timeout, max_duration,
     in_rate, in_burst, out_rate, out_burst) = struct.unpack_from('=8I', data, o); o += 32

    duration, _ = struct.unpack_from('=Ii', data, o); o += 8

    (in_pk_lo,  in_pk_hi,
     in_by_lo,  in_by_hi,
     out_pk_lo, out_pk_hi,
     out_by_lo, out_by_hi,
     psid_lo,   psid_hi) = struct.unpack_from('=10I', data, o); o += 40

    service_name = data[o:o+32].rstrip(b'\x00').decode('utf-8', errors='replace') or None

    return {
        'type':              ev_type,
        'session_id':        session_id,
        'cookie':            cookie,
        'ipaddr':            ipaddr,
        'nat_ipaddr':        nat_ipaddr,
        'macaddr':           macaddr if macaddr != '000000000000' else None,
        'flags':             flags,
        'port_number':       port_number,
        'alive_interval':    alive_interval,
        'idle_timeout':      idle_timeout,
        'max_duration':      max_duration,
        'in_rate':           in_rate,
        'in_burst':          in_burst,
        'out_rate':          out_rate,
        'out_burst':         out_burst,
        'duration':          duration,
        'in_packets':        (in_pk_hi << 32) | in_pk_lo,
        'in_bytes':          (in_by_hi << 32) | in_by_lo,
        'out_packets':       (out_pk_hi << 32) | out_pk_lo,
        'out_bytes':         (out_by_hi << 32) | out_by_lo,
        'service_name':      service_name,
        'parent_session_id': f'{psid_hi:08X}{psid_lo:08X}' if (psid_lo or psid_hi) else None,
    }


def parse_event(data: bytes) -> dict:
    length, nltype, nlflags, nlseq, nlpid = _unpack_nlmsghdr(data)
    ev = unpack_event(data[NL_HDR_LEN:])
    ev.update(nlhdr_len=length, nlhdr_type=nltype,
              nlhdr_flags=nlflags, nlhdr_seq=nlseq, nlhdr_pid=nlpid)
    return ev


# ─── public socket API ────────────────────────────────────────────────────────

# fd → portid mapping (socket objects are C extensions; can't set attributes on them)
_portid_cache: dict = {}


def open_auth_socket() -> socket.socket:
    """Minimal send-only Netlink socket for auth worker threads."""
    sk = socket.socket(AF_NETLINK, socket.SOCK_RAW, ISG_NETLINK_MAIN)
    # If bind rmem growth until overflow
    # sk.bind((0, 0))
    portid = sk.getsockname()[0] or os.getpid()
    _portid_cache[sk.fileno()] = portid
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                  struct.pack('ll', 5, 0))
    return sk


def open_socket() -> socket.socket:
    sk = socket.socket(AF_NETLINK, socket.SOCK_RAW, ISG_NETLINK_MAIN)
    sk.bind((0, 0))
    # getsockname() returns 0 on Python 3.8 / some kernels: netlink autobind
    # does not commit the portid until after the first send().
    # Perl avoids this by always using $$ (process PID) in the message header.
    portid = sk.getsockname()[0] or os.getpid()
    _portid_cache[sk.fileno()] = portid
    try:
        rmem_max = int(open('/proc/sys/net/core/rmem_max').read())
    except OSError:
        rmem_max = 16777216
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rmem_max)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                  struct.pack('ll', 5, 0))
    return sk


def _portid(sk: socket.socket) -> int:
    """Portid to embed in outgoing Netlink message headers."""
    return _portid_cache.get(sk.fileno(), 0) or os.getpid()


def send_only(sk: socket.socket, ev: dict) -> None:
    """Fire-and-forget: send event, do not read a reply."""
    base = _blank()
    base.update(ev)
    sk.sendto(_pack_nlmsg(pack_event(base), _portid(sk)), (0, 0))


def send_event(sk: socket.socket, ev: dict, timeout: float = 10) -> dict:
    """Send event and return the parsed kernel reply."""
    base = _blank()
    base.update(ev)
    sk.sendto(_pack_nlmsg(pack_event(base), _portid(sk)), (0, 0))
    sk.settimeout(timeout)
    try:
        data = sk.recv(16384)
    finally:
        sk.settimeout(None)
    return parse_event(data)


def get_totals(sk: socket.socket, timeout: float = 2.0) -> tuple[dict | None, list]:
    """
    Send EVENT_SESS_GETTOTALS; return (totals_ev, top_sessions).

    totals_ev is the EVENT_SESS_TOTALS dict (in_bytes/out_bytes),
    or None if the kernel does not support this event (old module).
    top_sessions is a list of EVENT_SESS_INFO dicts (top-N by traffic).
    Raises OSError on socket error; returns (None, []) on timeout.
    """
    base = _blank()
    base['type'] = EVENT_SESS_GETTOTALS
    sk.sendto(_pack_nlmsg(pack_event(base), _portid(sk)), (0, 0))

    msg_sz  = NL_HDR_LEN + IN_EVENT_MSG_LEN
    totals  = None
    top     = []
    sk.settimeout(timeout)
    try:
        while True:
            data = sk.recv(16384)
            n    = len(data)
            if n == NL_HDR_LEN:
                _, nltype, *_ = _unpack_nlmsghdr(data)
                if nltype == NLMSG_DONE:
                    break
                continue
            if n < msg_sz or n % msg_sz:
                continue
            for i in range(n // msg_sz):
                ev_parsed = parse_event(data[i * msg_sz:(i + 1) * msg_sz])
                t = ev_parsed['type']
                if t == EVENT_SESS_TOTALS:
                    totals = ev_parsed
                elif t == EVENT_SESS_INFO and ev_parsed.get('ipaddr'):
                    top.append(ev_parsed)
                if ev_parsed['nlhdr_type'] == NLMSG_DONE:
                    return totals, top
    except (socket.timeout, KeyboardInterrupt):
        pass
    finally:
        sk.settimeout(None)
    return totals, top


def get_list(sk: socket.socket, ev: dict, timeout: float = 10) -> tuple[list, bool]:
    """
    Send a list request; collect all SESSION_INFO events.

    Returns (results, terminated) where *terminated* is True when the kernel
    sent NLMSG_DONE (clean end-of-list) and False on timeout / interrupt.

    Handles two termination patterns:
      1. Bare NLMSG_DONE header (16 bytes, no payload).
      2. An EVENT_SESS_INFO message with nlhdr_type == NLMSG_DONE.
    """
    base = _blank()
    base.update(ev)
    sk.sendto(_pack_nlmsg(pack_event(base), _portid(sk)), (0, 0))

    msg_sz     = NL_HDR_LEN + IN_EVENT_MSG_LEN
    results    = []
    terminated = False
    sk.settimeout(timeout)

    try:
        while True:
            data = sk.recv(16384)
            n    = len(data)

            # Pattern 1: bare NLMSG_DONE (standard netlink end-of-list)
            if n == NL_HDR_LEN:
                _, nltype, *_ = _unpack_nlmsghdr(data)
                if nltype == NLMSG_DONE:
                    terminated = True
                    break
                continue

            if n < msg_sz or n % msg_sz:
                continue

            done = False
            for i in range(n // msg_sz):
                ev_parsed = parse_event(data[i * msg_sz:(i + 1) * msg_sz])
                if ev_parsed['type'] == EVENT_SESS_INFO:
                    if ev_parsed['ipaddr'] != 0:
                        results.append(ev_parsed)
                    # Pattern 2: ISG-specific NLMSG_DONE inside payload
                    if ev_parsed['nlhdr_type'] == NLMSG_DONE:
                        done = True
                        break
            if done:
                terminated = True
                break
    except (socket.timeout, KeyboardInterrupt):
        pass
    finally:
        sk.settimeout(None)

    return results, terminated
