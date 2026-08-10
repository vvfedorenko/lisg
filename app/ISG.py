#!/usr/bin/env python3
"""ISG session management CLI."""
from __future__ import annotations
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from src import isg

# Set to True to suppress all ANSI escape codes (via --no-color or config)
_no_color: bool = False


def _c(code: str, text: str) -> str:
    return text if _no_color else f'\033[{code}m{text}\033[0m'


USAGE = """\
Usage: {prog} [command [target]]

With no arguments: list all sessions.

Commands:
  show_count
  show_session  <IP | Virtual# | Session-ID>
  show_services <IP | Virtual# | Session-ID>
  monitor       [IP | Virtual# | Session-ID]  (no arg = total throughput view)
  clear         <IP | Virtual# | Session-ID>
  clear_all
  clear_unapproved
  change_rate   <IP | Virtual# | Session-ID> <in_kbps> <out_kbps>

Options:
  --no-color    Disable ANSI color output

Flags: A approved  X not-approved  S service  O svc-on  U online  T tagger  Z no-acct
"""

# ── formatting helpers ────────────────────────────────────────────────────────

_arp_table: dict = {}


def _load_arp_table() -> None:
    try:
        with open('/proc/net/arp') as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    _arp_table[parts[0]] = parts[3]
    except OSError:
        pass


def get_mac(ip: str) -> str:
    if not _arp_table:
        _load_arp_table()
    mac = _arp_table.get(ip)
    return mac if mac else _c('31', 'Not found')


def format_duration(seconds: int) -> str:
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f'{d:3d}d{_c("33", f"{h:02d}:{m:02d}:{s:02d}")}'


def format_octets(b: int) -> str:
    G, r = divmod(b, 1_000_000_000)
    M, r = divmod(r, 1_000_000)
    K, r = divmod(r, 1_000)
    return f'{G:8d}g{M:03d}.{K:03d}.{r:03d}'


def format_rate(rate: int) -> str:
    if rate >= 1_000_000_000:
        return f'{rate / 1_000_000_000:.3g}G'
    if rate >= 1_000_000:
        return f'{rate / 1_000_000:.3g}M'
    if rate >= 1_000:
        return f'{rate / 1_000:.3g}K'
    return str(rate)


def sprint_flags(ev: dict) -> str:
    f = ev.get('flags', 0)
    if not f:
        return _c('31', '✗') + ' X'
    if f & isg.IS_SERVICE:
        emoji, s = '', 'S'
    elif f & isg.IS_APPROVED_SESSION:
        emoji, s = _c('32', '✔') + ' ', 'A'
    else:
        emoji, s = '', ''
    s += 'O' if (f & isg.SERVICE_STATUS_ON) else ''
    s += 'U' if (f & isg.SERVICE_ONLINE)    else ''
    s += 'Z' if (f & isg.NO_ACCT)           else ''
    s += 'T' if (f & isg.SERVICE_TAGGER)    else ''
    return (emoji + s) if (emoji or s) else 'X'


# ── column definitions ────────────────────────────────────────────────────────
# Each entry: (key, header, visible_width, value_fn)
# visible_width=0 means last column — no trailing padding applied.

COLUMN_DEFS: list = [
    ('user_ip',    'User IP',                      15, lambda e: isg.long2ip(e['ipaddr'])),
    ('mac',        'MAC Address',                  17, lambda e: get_mac(isg.long2ip(e['ipaddr']))),
    ('nat_ip',     'NAT IP',                       15, lambda e: isg.long2ip(e['nat_ipaddr'])),
    ('port',       'Port',                         13, lambda e: 'Virtual' + str(e['port_number'])),
    ('session_id', 'Session-ID',                   16, lambda e: e['session_id']),
    ('duration',   '  Duration',                   12, lambda e: format_duration(e['duration'])),
    ('octets_in',  '       Octets-in',             20, lambda e: format_octets(e['in_bytes'])),
    ('octets_out', '       Octets-out',            20, lambda e: format_octets(e['out_bytes'])),
    ('rate_in',    'Rate-in',                       7, lambda e: format_rate(e['in_rate'])),
    ('rate_out',   'Rate-out',                      8, lambda e: format_rate(e['out_rate'])),
    ('service',    'Service',                      16, lambda e: e.get('service_name') or 'Main session'),
    ('flags',      'Flags',                         0, sprint_flags),
]

ALL_COLUMNS: list = [k for k, *_ in COLUMN_DEFS]

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _pad(s: str, width: int) -> str:
    """Left-align s to visible width, accounting for invisible ANSI codes."""
    visible = len(_ANSI_RE.sub('', s))
    return s + ' ' * max(0, width - visible)


def _print_table(rows: list, active: list) -> None:
    col_map = {k: (h, w, fn) for k, h, w, fn in COLUMN_DEFS}
    cols = [k for k in ALL_COLUMNS if k in active]

    # Header
    parts = []
    for i, key in enumerate(cols):
        h, w, _ = col_map[key]
        parts.append(_pad(h, w) if i < len(cols) - 1 else h)
    print(' '.join(parts))

    # Rows
    for e in rows:
        if e['type'] != isg.EVENT_SESS_INFO or not e['ipaddr']:
            continue
        parts = []
        for i, key in enumerate(cols):
            _, w, fn = col_map[key]
            val = str(fn(e))
            parts.append(_pad(val, w) if i < len(cols) - 1 else val)
        print(' '.join(parts))


# ── misc ──────────────────────────────────────────────────────────────────────

def parse_target(arg: str, ev: dict) -> None:
    m = re.match(r'^Virtual(\d+)$', arg)
    if m:
        ev['port_number'] = int(m.group(1))
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', arg):
        ev['ipaddr'] = isg.ip2long(arg)
    else:
        ev['session_id'] = isg.session_id_to_bytes(arg)


def main():
    global _no_color

    raw_args = sys.argv[1:]
    cli_no_color = '--no-color' in raw_args or '--no-colour' in raw_args
    args = [a for a in raw_args if a not in ('--no-color', '--no-colour')]

    # Read settings from config.yaml if present alongside this script
    active_columns = list(ALL_COLUMNS)
    status_path: str | None = None
    conf_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    if os.path.isfile(conf_path):
        try:
            import yaml
            with open(conf_path) as _f:
                _cfg = yaml.safe_load(_f) or {}
            _no_color = bool(_cfg.get('no_color_output', False))
            if 'columns' in _cfg and isinstance(_cfg['columns'], list):
                active_columns = [c for c in _cfg['columns'] if c in ALL_COLUMNS]
            pid_file = _cfg.get('pid_file', '/var/run/ISGd.pid')
            status_path = os.path.splitext(pid_file)[0] + '.status'
        except Exception:
            pass

    if cli_no_color:
        _no_color = True

    try:
        sk = isg.open_socket()
    except OSError as e:
        sys.exit(f'Cannot open netlink socket: {e}')

    ev = {}
    rc = 0

    if len(args) >= 2:
        parse_target(args[1], ev)

    try:
        if len(args) == 2 and args[0] == 'clear':
            ev['type'] = isg.EVENT_SESS_CLEAR
            rep = isg.send_event(sk, ev)
            if rep['type'] != isg.EVENT_KERNEL_ACK:
                print('clear: session not found', file=sys.stderr)
                rc = 1

        elif len(args) == 1 and args[0] == 'clear_all':
            sessions, _ = isg.get_list(sk, {'type': isg.EVENT_SESS_GETLIST})
            parent_sessions = [s for s in sessions if not (s.get('flags', 0) & isg.IS_SERVICE)]
            for s in parent_sessions:
                isg.send_only(sk, {'type': isg.EVENT_SESS_CLEAR,
                                   'port_number': s['port_number']})
            print(f'Cleared {len(parent_sessions)} sessions')

        elif len(args) == 1 and args[0] == 'clear_unapproved':
            sessions, _ = isg.get_list(sk, {'type': isg.EVENT_SESS_GETLIST})
            unapproved = [s for s in sessions
                          if not (s.get('flags', 0) & (isg.IS_SERVICE | isg.IS_APPROVED_SESSION))]
            for s in unapproved:
                isg.send_only(sk, {'type': isg.EVENT_SESS_CLEAR,
                                   'port_number': s['port_number']})
            print(f'Cleared {len(unapproved)} unapproved sessions')

        elif len(args) in (1, 2) and args[0] == 'monitor':
            from src import monitor
            if len(args) == 2:
                rc = monitor.run(sk, ev, args[1], no_color=_no_color)
            else:
                rc = monitor.run_global(sk, status_path=status_path, no_color=_no_color)

        elif len(args) == 4 and args[0] == 'change_rate':
            in_r  = int(args[2]) * 1000
            out_r = int(args[3]) * 1000
            ev.update(type=isg.EVENT_SESS_CHANGE,
                      in_rate=in_r,   in_burst=int(in_r  * 1.5),
                      out_rate=out_r, out_burst=int(out_r * 1.5))
            rep = isg.send_event(sk, ev)
            if rep['type'] != isg.EVENT_KERNEL_ACK:
                print('change_rate: session not found', file=sys.stderr)
                rc = 1

        elif len(args) == 1 and args[0] == 'show_count':
            rep   = isg.send_event(sk, {'type': isg.EVENT_SESS_GETCOUNT})
            act   = isg.ntohl(rep['ipaddr'])
            unap  = isg.ntohl(rep['nat_ipaddr'])
            dying = rep['port_number']
            noacc = rep['alive_interval']
            print(f'Approved:\t{act - noacc}')
            print(f'Unapproved:\t{unap}')
            print(f'Dying:\t\t{dying}')
            print(f'No-accounting:\t{noacc}')
            print(f'Total:\t\t{act + unap + dying}')

        elif (len(args) == 0
              or (len(args) in (1, 2) and args[0] in ('show_session', 'show_services'))):
            ev['type'] = (isg.EVENT_SERV_GETLIST
                          if args and args[0] == 'show_services'
                          else isg.EVENT_SESS_GETLIST)
            rows, ok = isg.get_list(sk, ev, timeout=3)
            if not ok:
                print('Kernel did not respond — is the ISG module loaded?',
                      file=sys.stderr)
                rc = 1
            elif not rows:
                print('No active sessions.')
            else:
                _print_table(rows, active_columns)

        else:
            print(USAGE.format(prog=sys.argv[0]), file=sys.stderr)
            rc = 1

    except OSError as e:
        print(f'Error: {e}', file=sys.stderr)
        rc = 1
    finally:
        sk.close()

    sys.exit(rc)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
