"""RADIUS packet builder and protocol constants shared across backends."""
from __future__ import annotations

import hashlib
import logging
import os

try:
    import pyrad.packet as rp
except ImportError:
    raise ImportError('pyrad required: pip install pyrad')

from . import isg

log = logging.getLogger(__name__)

# RADIUS code ↔ name maps
NAMES: dict[int, str] = {
    1: 'Access-Request',     2: 'Access-Accept',      3: 'Access-Reject',
    4: 'Accounting-Request', 5: 'Accounting-Response',
    40: 'Disconnect-Request', 41: 'Disconnect-ACK', 42: 'Disconnect-NAK',
    43: 'CoA-Request',        44: 'CoA-ACK',         45: 'CoA-NAK',
}
CODES: dict[str, int] = {v: k for k, v in NAMES.items()}

# Error-Cause attribute values (RFC 3576, type=101)
ERROR_CAUSES: dict[str, int] = {
    'Unsupported-Attribute':        401,
    'Missing-Attribute':            402,
    'NAS-Identification-Mismatch':  403,
    'Invalid-Request':              404,
    'Unsupported-Service':          405,
    'Unsupported-Extension':        406,
    'Administratively-Prohibited':  501,
    'Session-Context-Not-Found':    503,
    'Session-Context-Not-Removable': 504,
    'Resources-Unavailable':        506,
}


def _encrypt_password(secret: bytes, authenticator: bytes, password: str) -> bytes:
    """RFC 2865 §5.2 PAP User-Password obfuscation."""
    pw = password.encode('utf-8') if isinstance(password, str) else password
    padded = pw + b'\x00' * (-len(pw) % 16)
    result, prev = b'', authenticator
    for i in range(0, len(padded), 16):
        block = hashlib.md5(secret + prev).digest()
        chunk = bytes(a ^ b for a, b in zip(block, padded[i:i+16]))
        result += chunk
        prev = chunk
    return result


def attr_get(pkt, name: str, default=None):
    """Safely retrieve the first value of a RADIUS attribute."""
    try:
        vals = pkt[name]
        return vals[0] if vals else default
    except (KeyError, IndexError, TypeError):
        return default


# ─── packet builder ───────────────────────────────────────────────────────────

def build(code: str, ev: dict, secret: bytes, rid: int,
          rad_dict, nas_ip: str, nas_id: str):
    username = isg.long2ip(ev.get('ipaddr', 0))

    pkt = (rp.AcctPacket(secret=secret, dict=rad_dict)
           if code == 'Accounting-Request'
           else rp.AuthPacket(secret=secret, dict=rad_dict))
    pkt.id = rid

    pkt['User-Name']          = username
    pkt['Calling-Station-Id'] = username
    pkt['Service-Type']       = 'Framed-User'
    pkt['NAS-IP-Address']     = nas_ip
    pkt['NAS-Identifier']     = nas_id
    pkt['Called-Station-Id']  = nas_id
    pkt['NAS-Port']           = ev.get('port_number', 0)
    pkt['NAS-Port-Type']      = 'Virtual'

    if ev.get('macaddr'):
        pkt.AddAttribute('Cisco-AVPair',
                         'client-mac-address=' + isg.format_mac(ev['macaddr'], 4))

    if code == 'Accounting-Request':
        pkt['Acct-Status-Type'] = {
            isg.EVENT_SESS_START:  'Start',
            isg.EVENT_SESS_UPDATE: 'Alive',
            isg.EVENT_SESS_STOP:   'Stop',
        }.get(ev.get('type'), 'Stop')

        if ev.get('nat_ipaddr'):
            pkt['Framed-IP-Address'] = isg.long2ip(ev['nat_ipaddr'])

        in_b  = ev.get('in_bytes', 0)
        out_b = ev.get('out_bytes', 0)
        pkt['Acct-Authentic']        = 'RADIUS'
        pkt['Acct-Session-Id']       = ev.get('session_id', '')
        pkt['Acct-Session-Time']     = ev.get('duration', 0)
        pkt['Acct-Input-Packets']    = ev.get('in_packets', 0)
        pkt['Acct-Output-Packets']   = ev.get('out_packets', 0)
        pkt['Acct-Input-Octets']     = in_b  & 0xFFFFFFFF
        pkt['Acct-Output-Octets']    = out_b & 0xFFFFFFFF
        pkt['Acct-Input-Gigawords']  = in_b  >> 32
        pkt['Acct-Output-Gigawords'] = out_b >> 32
        if ev.get('cookie'):
            pkt['Class'] = ev['cookie']
        pkt.AddAttribute('Cisco-Control-Info', f"I{in_b >> 32};{in_b & 0xFFFFFFFF}")
        pkt.AddAttribute('Cisco-Control-Info', f"O{out_b >> 32};{out_b & 0xFFFFFFFF}")
        if ev.get('parent_session_id'):
            pkt.AddAttribute('Cisco-AVPair', 'parent-session-id=' + ev['parent_session_id'])
        if ev.get('service_name'):
            pkt.AddAttribute('Cisco-Service-Info', 'N' + ev['service_name'])
    else:
        # Authenticator must be fixed before password encryption — both the
        # packet header and the RFC 2865 obfuscation must use the same value.
        if not pkt.authenticator:
            pkt.authenticator = os.urandom(16)
        pkt['User-Password'] = _encrypt_password(pkt.secret, pkt.authenticator, username)
        # RFC 3579 / CVE-2024-3596: newer FreeRADIUS requires Message-Authenticator.
        # Insert a zero placeholder; the real HMAC is computed after the packet is
        # fully assembled (see send_to_server).
        pkt['Message-Authenticator'] = b'\x00' * 16

    return pkt
