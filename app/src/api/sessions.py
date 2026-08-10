"""Netlink helpers for the REST API — each call opens its own socket."""
from __future__ import annotations

import re
from typing import Optional

from .. import isg
from .models import SessionFlags


# ── ARP table ─────────────────────────────────────────────────────────────────

def _arp_table() -> dict[str, str]:
    """Return {ip: mac_colon} from /proc/net/arp."""
    table: dict[str, str] = {}
    try:
        with open('/proc/net/arp') as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                    table[parts[0]] = parts[3]
    except OSError:
        pass
    return table


def _mac_colon(raw: Optional[str]) -> Optional[str]:
    """Convert 12-char hex string to aa:bb:cc:dd:ee:ff, or None."""
    if not raw or raw == '000000000000':
        return None
    h = raw.lower().replace(':', '').replace('-', '').replace('.', '')
    if len(h) != 12:
        return None
    return ':'.join(h[i:i+2] for i in range(0, 12, 2))


def _norm_mac(s: Optional[str]) -> str:
    """Normalise any MAC representation to 12 lowercase hex chars (None → '')."""
    if not s:
        return ''
    return re.sub(r'[:\-.]', '', s).lower()


def _decode_flags(f: int) -> SessionFlags:
    return SessionFlags(
        approved       = bool(f & isg.IS_APPROVED_SESSION),
        service        = bool(f & isg.IS_SERVICE),
        service_on     = bool(f & isg.SERVICE_STATUS_ON),
        service_online = bool(f & isg.SERVICE_ONLINE),
        no_accounting  = bool(f & isg.NO_ACCT),
        dying          = bool(f & isg.IS_DYING),
        tagger         = bool(f & isg.SERVICE_TAGGER),
    )


def _ev_to_info(ev: dict, arp: dict) -> dict:
    ip     = isg.long2ip(ev['ipaddr'])
    nat    = isg.long2ip(ev['nat_ipaddr']) if ev.get('nat_ipaddr') else None
    mac    = _mac_colon(ev.get('macaddr')) or arp.get(ip)
    return {
        'session_id':        ev['session_id'],
        'ip':                ip,
        'nat_ip':            nat,
        'mac':               mac,
        'port':              ev.get('port_number', 0),
        'duration':          ev.get('duration', 0),
        'in_bytes':          ev.get('in_bytes', 0),
        'out_bytes':         ev.get('out_bytes', 0),
        'in_packets':        ev.get('in_packets', 0),
        'out_packets':       ev.get('out_packets', 0),
        'in_rate':           ev.get('in_rate', 0),
        'out_rate':          ev.get('out_rate', 0),
        'in_burst':          ev.get('in_burst', 0),
        'out_burst':         ev.get('out_burst', 0),
        'alive_interval':    ev.get('alive_interval', 0),
        'idle_timeout':      ev.get('idle_timeout', 0),
        'max_duration':      ev.get('max_duration', 0),
        'flags':             _decode_flags(ev.get('flags', 0)),
        'service_name':      ev.get('service_name'),
        'parent_session_id': ev.get('parent_session_id'),
    }


# ── public helpers ────────────────────────────────────────────────────────────

def _s32(v: int) -> int:
    """Reinterpret an unsigned 32-bit kernel counter as signed (counters can go negative)."""
    return v if v < 0x80000000 else v - 0x100000000


def fetch_counts() -> dict:
    sk = isg.open_socket()
    try:
        rep     = isg.send_event(sk, {'type': isg.EVENT_SESS_GETCOUNT})
        act     = _s32(isg.ntohl(rep['ipaddr']))
        unap    = abs(_s32(isg.ntohl(rep['nat_ipaddr'])))
        dying   = rep.get('port_number', 0)
        no_acct = rep.get('alive_interval', 0)
        return {
            'approved':      act - no_acct,
            'unapproved':    unap,
            'dying':         dying,
            'no_accounting': no_acct,
            'total':         act + unap + dying,
        }
    finally:
        sk.close()


def fetch_all(limit: int = 1000, offset: int = 0) -> list[dict]:
    sk  = isg.open_socket()
    arp = _arp_table()
    try:
        rows, _ = isg.get_list(sk, {'type': isg.EVENT_SESS_GETLIST}, timeout=5)
        return [_ev_to_info(e, arp) for e in rows[offset:offset + limit]]
    finally:
        sk.close()


def find_session(id_str: str) -> Optional[dict]:
    """Return the first session matching ip / mac / session_id, or None."""
    arp = _arp_table()

    # IP — kernel supports O(1) hash lookup when ipaddr is set in the request
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', id_str):
        sk = isg.open_socket()
        try:
            rows, _ = isg.get_list(sk, {
                'type':   isg.EVENT_SESS_GETLIST,
                'ipaddr': isg.ip2long(id_str),
            }, timeout=2)
        finally:
            sk.close()
        for ev in rows:
            if ev.get('ipaddr') == isg.ip2long(id_str):
                return _ev_to_info(ev, arp)
        return None

    # Session-ID or MAC — no kernel-side index; need full scan
    sk = isg.open_socket()
    try:
        rows, _ = isg.get_list(sk, {'type': isg.EVENT_SESS_GETLIST}, timeout=5)
    finally:
        sk.close()

    # Session-ID — exactly 16 hex chars (checked before MAC, which also
    # accepts bare hex; a 16-char session-id must not be read as a MAC).
    if re.match(r'^[0-9A-Fa-f]{16}$', id_str):
        up = id_str.upper()
        for ev in rows:
            if ev['session_id'].upper() == up:
                return _ev_to_info(ev, arp)
        return None

    # MAC — 12 bare hex chars, or any length with : . - separators
    if re.match(r'^[0-9A-Fa-f]{12}$', id_str) \
            or re.match(r'^[0-9A-Fa-f]{1,2}([:.\-][0-9A-Fa-f]{1,2}){5}$', id_str):
        target = _norm_mac(id_str)
        for ev in rows:
            if _norm_mac(ev.get('macaddr')) == target:
                return _ev_to_info(ev, arp)
        return None

    return None


def _session_ev(session: dict) -> dict:
    """Build a minimal kernel event targeting a known session by port and IP."""
    return {
        'port_number': session['port'],
        'ipaddr':      isg.ip2long(session['ip']),
    }


def apply_update(session: dict, upd) -> dict:
    """Apply SessionUpdate fields to the kernel. Returns a dict describing what was done."""
    actions: list[str] = []
    sk = isg.open_socket()
    try:
        # ── block takes precedence ─────────────────────────────────────────
        if upd.block:
            ev = _session_ev(session)
            ev['type'] = isg.EVENT_SESS_CLEAR
            isg.send_event(sk, ev)
            actions.append('block')
            return {'actions': actions}

        # ── approve (with optional rate) ───────────────────────────────────
        if upd.approve:
            ev = _session_ev(session)
            ev['type']  = isg.EVENT_SESS_APPROVE
            ev['flags'] = 0
            _apply_rates(ev, upd)
            isg.send_only(sk, ev)
            actions.append('approve')

        # ── rate-only change ───────────────────────────────────────────────
        elif upd.in_kbps is not None or upd.out_kbps is not None:
            ev = _session_ev(session)
            ev['type'] = isg.EVENT_SESS_CHANGE
            _apply_rates(ev, upd)
            isg.send_event(sk, ev)
            actions.append('rate')

    finally:
        sk.close()

    return {'actions': actions}


_UINT32_MAX = 4_294_967_295


def _apply_rates(ev: dict, upd) -> None:
    if upd.in_kbps is not None:
        r = upd.in_kbps * 1000
        ev['in_rate']  = r
        ev['in_burst'] = min(int(r * 1.5), _UINT32_MAX)
    if upd.out_kbps is not None:
        r = upd.out_kbps * 1000
        ev['out_rate']  = r
        ev['out_burst'] = min(int(r * 1.5), _UINT32_MAX)
