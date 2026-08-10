"""Real-time throughput monitor with nload-style ASCII graphs.

Two modes:
  run()        — per-session view for a specific IP/Virtual#/Session-ID
  run_global() — system-wide view: total throughput + top sessions
"""
from __future__ import annotations

import datetime
import re
import select
import shutil
import sys
import time
from collections import deque

from . import isg

# 9 levels: index 0 = blank, 1..8 = ⅛..full block — gives sub-row resolution.
_BLOCKS = ' ▁▂▃▄▅▆▇█'


def _s32(v: int) -> int:
    """Reinterpret unsigned 32-bit kernel counter as signed (can go negative)."""
    return v if v < 0x80000000 else v - 0x100000000


# ── formatting ────────────────────────────────────────────────────────────────

def _fmt_bps(bps: float) -> str:
    if bps >= 1e9:
        return f'{bps / 1e9:6.2f} Gbit/s'
    if bps >= 1e6:
        return f'{bps / 1e6:6.2f} Mbit/s'
    if bps >= 1e3:
        return f'{bps / 1e3:6.2f} Kbit/s'
    return f'{bps:6.0f}  bit/s'


def _fmt_bytes(b: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if b < 1000:
            return f'{b:6.1f} {unit}'
        b /= 1000
    return f'{b:6.1f} PB'


def _fmt_axis(bps: float) -> str:
    """Compact bits/s label for the Y-axis scale (e.g. 5.0M, 500K)."""
    if bps >= 1e9:
        return f'{bps / 1e9:.1f}G'
    if bps >= 1e6:
        return f'{bps / 1e6:.1f}M'
    if bps >= 1e3:
        return f'{bps / 1e3:.0f}K'
    return f'{bps:.0f}'


def _c(code: str, text: str, no_color: bool) -> str:
    return text if no_color else f'\033[{code}m{text}\033[0m'


# ── session lookup ────────────────────────────────────────────────────────────

def _match(row: dict, arg: str) -> bool:
    if re.match(r'^Virtual(\d+)$', arg):
        return row.get('port_number') == int(arg[7:])
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', arg):
        return row.get('ipaddr') == isg.ip2long(arg)
    if re.match(r'^[0-9A-Fa-f]{16}$', arg):
        return str(row.get('session_id', '')).upper() == arg.upper()
    return False


def _find(sk, target_ev: dict, arg: str):
    rows, _ = isg.get_list(sk, {**target_ev, 'type': isg.EVENT_SESS_GETLIST},
                           timeout=2)
    for r in rows:
        if r['type'] == isg.EVENT_SESS_INFO and r.get('ipaddr') and _match(r, arg):
            return r
    return None


def _services_for(sk, target_ev: dict, parent_ipaddr: int) -> list:
    """Service sub-sessions belonging to the monitored session."""
    try:
        rows, _ = isg.get_list(sk, {**target_ev, 'type': isg.EVENT_SERV_GETLIST},
                               timeout=2)
    except OSError:
        return []
    return [r for r in rows
            if r['type'] == isg.EVENT_SESS_INFO
            and r.get('service_name')
            and r.get('ipaddr') == parent_ipaddr]


def _sess_flags(ev: dict, no_color: bool) -> str:
    f = ev.get('flags', 0)
    if f & isg.IS_APPROVED_SESSION:
        status = _c('32', 'A', no_color)
    else:
        status = _c('31', 'X', no_color)
    s = status
    s += 'Z' if f & isg.NO_ACCT    else ''
    s += 'D' if f & isg.IS_DYING   else ''
    return s


def _svc_flags(ev: dict) -> str:
    f = ev.get('flags', 0)
    s = ''
    s += 'O' if f & isg.SERVICE_STATUS_ON else ''
    s += 'U' if f & isg.SERVICE_ONLINE   else ''
    s += 'T' if f & isg.SERVICE_TAGGER   else ''
    s += 'Z' if f & isg.NO_ACCT          else ''
    return s or '-'


def _mac_of(ev: dict) -> str:
    """MAC from the session (kernel) or, failing that, the ARP table."""
    raw = ev.get('macaddr')
    if raw and raw != '000000000000':
        h = raw.lower()
        return ':'.join(h[i:i + 2] for i in range(0, 12, 2))
    ip = isg.long2ip(ev.get('ipaddr', 0))
    try:
        with open('/proc/net/arp') as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[0] == ip and p[3] != '00:00:00:00:00:00':
                    return p[3]
    except OSError:
        pass
    return '-'


# ── graph rendering ───────────────────────────────────────────────────────────

_LABEL_W = 6   # width of the Y-axis label column


def _graph_block(samples: deque, ceiling: float, width: int, height: int,
                 color: str, no_color: bool) -> list[str]:
    """
    Render a labelled bar graph.

    Layout per data row:  ``<value>│<bars>``  (value = rate at that row's top)
    Final row is a baseline axis:  ``     0└────────``
    `width` is the total line width budget (label + axis + bars).
    """
    bw = max(10, width - _LABEL_W - 1)                  # bar area width
    vals = list(samples)[-bw:]
    vals = [0.0] * (bw - len(vals)) + vals              # left-pad with blanks
    ceiling = ceiling if ceiling > 0 else 1.0

    lines = []
    for r in range(height - 1, -1, -1):                 # top row first
        top_val = ceiling * (r + 1) / height            # rate at top of this row
        label = _fmt_axis(top_val).rjust(_LABEL_W)
        chars = []
        for v in vals:
            level = min(v / ceiling, 1.0) * height
            if level >= r + 1:
                chars.append(_BLOCKS[8])
            elif level <= r:
                chars.append(' ')
            else:
                idx = max(1, min(8, round((level - r) * 8)))
                chars.append(_BLOCKS[idx])
        bar = ''.join(chars)
        if not no_color:
            bar = f'\033[{color}m{bar}\033[0m'
        lines.append(f'{_c("90", label, no_color)}{_c("90", "│", no_color)}{bar}')

    # baseline axis (0 at the bottom-left)
    base = _c('90', '0'.rjust(_LABEL_W) + '└' + '─' * bw, no_color)
    lines.append(base)
    return lines


# ── main loop ─────────────────────────────────────────────────────────────────

def run(sk, target_ev: dict, arg: str, interval: float = 1.0,
        no_color: bool = False) -> int:
    is_tty = sys.stdin.isatty()
    old_term = None
    if is_tty:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_term = termios.tcgetattr(fd)
        tty.setcbreak(fd)

    sys.stdout.write('\033[?25l')                       # hide cursor
    in_hist:  deque = deque(maxlen=400)
    out_hist: deque = deque(maxlen=400)
    prev = None                                          # (t, in_bytes, out_bytes)
    last_seen = None
    services: list = []
    status_msg    = ''
    pending       = None     # (footer_msg, action_fn) — awaiting y/N
    editing       = None     # [label, buffer] — interactive rate input

    HELP = " [q]uit  [c]lear  [a]pprove/block  [s]haper  [r]eset-graph"

    def cleanup():
        sys.stdout.write('\033[?25h\033[0m\n')          # show cursor, reset
        sys.stdout.flush()
        if old_term is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term)

    def do_clear() -> str:
        nonlocal prev
        try:
            isg.send_event(sk, {**target_ev, 'type': isg.EVENT_SESS_CLEAR})
            in_hist.clear(); out_hist.clear(); prev = None
            return 'session cleared'
        except OSError as e:
            return f'clear failed: {e}'

    def do_approve() -> str:
        try:
            isg.send_only(sk, {**target_ev, 'type': isg.EVENT_SESS_APPROVE})
            return 'session approved'
        except OSError as e:
            return f'approve failed: {e}'

    def apply_rate(buf: str) -> str:
        nums = re.findall(r'\d+(?:\.\d+)?', buf)
        if len(nums) == 1:                       # one value → both directions
            in_m = out_m = float(nums[0])
        elif len(nums) == 2:
            in_m, out_m = float(nums[0]), float(nums[1])
        else:
            return 'shaper: enter "<mbit>" or "<in> <out>"'
        in_r, out_r = int(in_m * 1_000_000), int(out_m * 1_000_000)
        try:
            isg.send_event(sk, {**target_ev, 'type': isg.EVENT_SESS_CHANGE,
                                 'in_rate':  in_r,  'in_burst':  int(in_r  * 1.5),
                                 'out_rate': out_r, 'out_burst': int(out_r * 1.5)})
            return f'shaper set {in_m:g}/{out_m:g} Mbit/s'
        except OSError as e:
            return f'shaper change failed: {e}'

    def footer() -> tuple:
        if editing is not None:
            return f" {editing[0]}{editing[1]}_", '36'
        if pending is not None:
            return f" {pending[0]}   [y/N]", '31'
        return (HELP + (f"    — {status_msg}" if status_msg else ''), '90')

    try:
        while True:
            t = time.monotonic()
            sess = _find(sk, target_ev, arg)
            if sess:
                last_seen = sess
                services = _services_for(sk, target_ev, sess['ipaddr'])
                if prev:
                    dt = max(t - prev[0], 1e-6)
                    din  = max(sess['in_bytes']  - prev[1], 0)
                    dout = max(sess['out_bytes'] - prev[2], 0)
                    in_hist.append(din  * 8 / dt)
                    out_hist.append(dout * 8 / dt)
                prev = (t, sess['in_bytes'], sess['out_bytes'])
            else:
                services = []

            foot, foot_color = footer()
            _render(last_seen, arg, in_hist, out_hist, no_color,
                    services, foot, foot_color)

            # wait `interval`, polling stdin for hotkeys
            deadline = t + interval
            redraw = False
            while not redraw:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not (is_tty and select.select([sys.stdin], [], [], remaining)[0]):
                    continue
                ch = sys.stdin.read(1)

                # ── interactive rate entry ──────────────────────────────────
                if editing is not None:
                    if ch in ('\r', '\n'):
                        status_msg = apply_rate(editing[1]); editing = None
                    elif ch == '\x1b':                  # Esc — cancel
                        status_msg = 'rate edit cancelled'; editing = None
                    elif ch in ('\x7f', '\x08'):        # Backspace
                        editing[1] = editing[1][:-1]
                    elif ch.isdigit() or ch == '.' or ch in ' ,/':
                        editing[1] += (' ' if ch in ',/' else ch)
                    redraw = True

                # ── y/N confirmation ────────────────────────────────────────
                elif pending is not None:
                    status_msg = pending[1]() if ch in ('y', 'Y') else 'cancelled'
                    pending = None
                    redraw = True

                # ── plain hotkeys ───────────────────────────────────────────
                elif ch in ('q', 'Q', '\x03'):
                    return 0
                elif ch in ('c', 'C'):
                    pending = (f"Clear session '{arg}' ?", do_clear)
                    status_msg = ''; redraw = True
                elif ch in ('a', 'A'):
                    if sess is None:
                        status_msg = 'no active session'
                    elif sess.get('flags', 0) & isg.IS_APPROVED_SESSION:
                        pending = (f"Block (disconnect) '{arg}' ?", do_clear)
                    else:
                        status_msg = do_approve()
                    redraw = True
                elif ch in ('s', 'S'):
                    editing = ['set shaper Mbit/s (one value or in out): ', '']
                    redraw = True
                elif ch in ('r', 'R'):
                    in_hist.clear(); out_hist.clear(); prev = None
                    status_msg = 'graph reset'; redraw = True
    except (KeyboardInterrupt, OSError):
        return 0
    finally:
        cleanup()


def _render(sess, arg: str, in_hist: deque, out_hist: deque,
            no_color: bool, services: list = (),
            footer: str = '', footer_color: str = '90') -> None:
    cols, lines = shutil.get_terminal_size((80, 24))
    # graph lines are indented one space; keep total <= cols-1 to avoid the
    # terminal auto-wrap-at-last-column quirk (which inserts blank lines).
    gw = max(20, cols - 2)

    def stats(hist):
        if not hist:
            return 0.0, 0.0, 0.0
        return hist[-1], sum(hist) / len(hist), max(hist)

    in_cur,  in_avg,  in_max  = stats(in_hist)
    out_cur, out_avg, out_max = stats(out_hist)

    # graph ceiling: shaper rate if set, else rolling max + 20% headroom
    in_cap  = sess['in_rate']  if sess and sess.get('in_rate')  else 0
    out_cap = sess['out_rate'] if sess and sess.get('out_rate') else 0
    in_ceil  = in_cap  or (in_max  * 1.2 or 1)
    out_ceil = out_cap or (out_max * 1.2 or 1)

    sep = '─' * gw
    out = ['\033[H']                                    # cursor home

    title = f"ISG Monitor — {arg}"
    out.append(_c('1', title, no_color) + '\033[K')
    out.append(_c('90', sep, no_color) + '\033[K')

    if sess is None:
        out.append(_c('31', ' session not found — waiting…', no_color) + '\033[K')
    else:
        ip   = isg.long2ip(sess['ipaddr'])
        nat  = isg.long2ip(sess['nat_ipaddr']) if sess.get('nat_ipaddr') else '-'
        dur  = sess.get('duration', 0)
        d, h = divmod(dur, 86400)
        hh, m = divmod(h, 3600)
        mm, ss = divmod(m, 60)
        dur_s = f'{d}d{hh:02d}:{mm:02d}:{ss:02d}'

        p1 = f" IP: {ip:<15}  NAT: {nat:<15}  MAC: {_mac_of(sess)}"
        p2 = (f"Session: {sess.get('session_id','-')}  Service: {sess.get('service_name') or 'Main'}"
              f"  Dur: {dur_s}  In: {_fmt_bytes(sess['in_bytes'])}  Out: {_fmt_bytes(sess['out_bytes'])}"
              f"  [{_sess_flags(sess, no_color)}]")
        if len(p1) + 2 + len(p2) <= cols - 1:
            out.append(p1 + '  ' + p2 + '\033[K')
        else:
            out.append(p1 + '\033[K')
            out.append(' ' + p2 + '\033[K')

        cap_in  = f"cap {_fmt_bps(in_cap)}"  if in_cap  else "uncapped"
        cap_out = f"cap {_fmt_bps(out_cap)}" if out_cap else "uncapped"
        in_s  = (f" IN   cur {_fmt_bps(in_cur)}  avg {_fmt_bps(in_avg)}"
                 f"  max {_fmt_bps(in_max)}  [{cap_in}]")
        out_s = (f" OUT  cur {_fmt_bps(out_cur)}  avg {_fmt_bps(out_avg)}"
                 f"  max {_fmt_bps(out_max)}  [{cap_out}]")
        if len(in_s) + 3 + len(out_s) - 1 <= cols - 1:
            out.append(_c('32', in_s, no_color) + '   '
                       + _c('36', out_s.lstrip(), no_color) + '\033[K')
        else:
            out.append(_c('32', in_s, no_color) + '\033[K')
            out.append(_c('36', out_s, no_color) + '\033[K')

        # Per-service shaper rates (sub-sessions of this session)
        if services:
            out.append(_c('1', " Services (shaper in / out):", no_color) + '\033[K')
            for s in services:
                nm = (s.get('service_name') or '?')[:20]
                line = (f"   {nm:<20} in {_fmt_bps(s.get('in_rate', 0))}"
                        f"  out {_fmt_bps(s.get('out_rate', 0))}"
                        f"  [{_svc_flags(s)}]")
                out.append(_c('33', line, no_color) + '\033[K')

    out.append(_c('90', sep, no_color) + '\033[K')

    # split remaining vertical space between the two graphs
    #   each graph: 1 title + gh data rows + 1 baseline; +1 footer
    used = len(out) + 2 * 2 + 1
    gh = max(3, (lines - used) // 2)

    out.append(_c('32', " Incoming", no_color) + '\033[K')
    for row in _graph_block(in_hist, in_ceil, gw, gh, '32', no_color):
        out.append(row + '\033[K')

    out.append(_c('36', " Outgoing", no_color) + '\033[K')
    for row in _graph_block(out_hist, out_ceil, gw, gh, '36', no_color):
        out.append(row + '\033[K')

    out.append(_c(footer_color, footer, no_color) + '\033[K')
    out.append('\033[J')                                # clear to end of screen

    sys.stdout.write('\n'.join(out))
    sys.stdout.flush()


# ── global monitor ────────────────────────────────────────────────────────────

def run_global(sk, interval: float = 1.0, no_color: bool = False,
               status_path: str | None = None) -> int:
    """System-wide monitor: total IN/OUT throughput + top sessions by rate."""
    is_tty = sys.stdin.isatty()
    old_term = None
    if is_tty:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_term = termios.tcgetattr(fd)
        tty.setcbreak(fd)

    sys.stdout.write('\033[?25l')
    in_hist:    deque = deque(maxlen=400)
    out_hist:   deque = deque(maxlen=400)
    prev_total: tuple | None = None   # (in_bytes, out_bytes) from last GETTOTALS
    prev_top:   dict  = {}            # {ipaddr: (in_bytes, out_bytes)}
    prev_t:     float = 0.0
    top_rates:  list  = []            # [(ipaddr, (in_bps, out_bps))]
    counts:     dict | None = None
    backends:   dict | None = None
    status_msg: str   = ''

    HELP = " [q]uit  [r]eset-graph"

    def cleanup():
        sys.stdout.write('\033[?25h\033[0m\n')
        sys.stdout.flush()
        if old_term is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term)

    try:
        while True:
            t = time.monotonic()

            # Session counts
            try:
                rep   = isg.send_event(sk, {'type': isg.EVENT_SESS_GETCOUNT})
                act   = _s32(isg.ntohl(rep['ipaddr']))
                unap  = abs(_s32(isg.ntohl(rep['nat_ipaddr'])))
                dying = rep.get('port_number', 0)
                noacc = rep.get('alive_interval', 0)
                counts = {
                    'total':      act + unap + dying,
                    'approved':   max(0, act - noacc),
                    'unapproved': unap,
                    'dying':      dying,
                    'no_acct':    noacc,
                }
            except OSError:
                pass

            # ── totals + top-N via single EVENT_SESS_GETTOTALS call ──────────
            try:
                totals_ev, top_sess = isg.get_totals(sk, timeout=2.0)
            except OSError:
                totals_ev, top_sess = None, []

            if totals_ev is not None:
                ib_total = totals_ev['in_bytes']
                ob_total = totals_ev['out_bytes']
                if prev_total is not None and prev_t > 0:
                    dt = max(t - prev_t, 1e-6)
                    in_hist.append(max(ib_total - prev_total[0], 0) * 8 / dt)
                    out_hist.append(max(ob_total - prev_total[1], 0) * 8 / dt)
                prev_total = (ib_total, ob_total)

                # compute per-session rates for top-N display
                new_top: dict = {}
                cur_rates: dict = {}
                for r in top_sess:
                    ip = r['ipaddr']
                    ib, ob = r['in_bytes'], r['out_bytes']
                    new_top[ip] = (ib, ob)
                    if prev_t > 0 and ip in prev_top:
                        dt2  = max(t - prev_t, 1e-6)
                        ibps = max(ib - prev_top[ip][0], 0) * 8 / dt2
                        obps = max(ob - prev_top[ip][1], 0) * 8 / dt2
                        cur_rates[ip] = (ibps, obps)
                top_rates = sorted(cur_rates.items(),
                                   key=lambda kv: kv[1][0] + kv[1][1],
                                   reverse=True)
                prev_top = new_top
                prev_t = t

            if status_path:
                try:
                    import json
                    with open(status_path) as _sf:
                        backends = json.load(_sf)
                except (OSError, ValueError):
                    pass

            _render_global(counts, in_hist, out_hist, top_rates, backends, no_color,
                           HELP + (f'    — {status_msg}' if status_msg else ''))

            deadline = t + interval
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not (is_tty and select.select([sys.stdin], [], [], remaining)[0]):
                    continue
                ch = sys.stdin.read(1)
                if ch in ('q', 'Q', '\x03'):
                    return 0
                elif ch in ('r', 'R'):
                    in_hist.clear(); out_hist.clear()
                    prev_bytes.clear(); prev_t = 0.0
                    status_msg = 'graph reset'
                    break

    except (KeyboardInterrupt, OSError):
        return 0
    finally:
        cleanup()


def _render_global(counts: dict | None, in_hist: deque, out_hist: deque,
                   top_rates: list, backends: dict | None,
                   no_color: bool, footer: str = '') -> None:
    cols, lines = shutil.get_terminal_size((80, 24))
    gw = max(20, cols - 2)
    sep = '─' * gw

    def stats(hist):
        if not hist:
            return 0.0, 0.0, 0.0
        return hist[-1], sum(hist) / len(hist), max(hist)

    in_cur,  in_avg,  in_max  = stats(in_hist)
    out_cur, out_avg, out_max = stats(out_hist)
    in_ceil  = (in_max  * 1.2) or 1.0
    out_ceil = (out_max * 1.2) or 1.0

    now = datetime.datetime.now().strftime('%H:%M:%S')
    out = ['\033[H']
    out.append(_c('1', f'ISG Global Monitor   {now}', no_color) + '\033[K')
    out.append(_c('90', sep, no_color) + '\033[K')

    if counts is not None:
        cs = (f" Sessions  total {counts['total']}"
              f"  approved {_c('32', str(counts['approved']), no_color)}"
              f"  unapproved {_c('31', str(counts['unapproved']), no_color)}"
              f"  dying {counts['dying']}")
        out.append(cs + '\033[K')
    else:
        out.append(_c('31', ' kernel not responding', no_color) + '\033[K')

    if backends:
        file_age = max(0.0, time.time() - backends.get('written_at', time.time()))

        def _fmt_ago(ago, extra=0.0):
            if ago is None:
                return _c('90', '     --', no_color)
            total = ago + extra
            if total < 60:
                return f'{total:5.1f}s'
            return f'{total/60:5.1f}m'

        def _backend_line(role, b):
            ok_ago  = _fmt_ago(b.get('last_ok_ago'),  file_age)
            err_ago = _fmt_ago(b.get('last_err_ago'), file_age)
            n_err   = b.get('err', 0)
            err_col = '31' if n_err > 0 else '90'
            err_s   = _c(err_col, f'err {n_err:>4}', no_color)
            tot_s   = _c('90', f'{b.get("total_rate", 0.0):5.2f}/s', no_color)
            cb_open = b.get('circuit_open', False)
            cb_s    = (_c('31;1', f" OPEN {b['circuit_open_for']:.0f}s", no_color)
                       if cb_open else '')
            return (f"  {role:<4} {b.get('label', '?'):<28}"
                    f"  {tot_s}"
                    f"  ok {b.get('ok', 0):>6}"
                    f"  {err_s}"
                    f"  last ok {ok_ago}"
                    f"  last err {err_ago}"
                    f"{cb_s}")

        for b in backends.get('auth', []):
            out.append(_backend_line('auth', b) + '\033[K')
        for b in backends.get('acct', []):
            out.append(_backend_line('acct', b) + '\033[K')

    in_s  = (f" IN   cur {_fmt_bps(in_cur)}  avg {_fmt_bps(in_avg)}"
             f"  max {_fmt_bps(in_max)}")
    out_s = (f" OUT  cur {_fmt_bps(out_cur)}  avg {_fmt_bps(out_avg)}"
             f"  max {_fmt_bps(out_max)}")
    if len(in_s) + 3 + len(out_s) - 1 <= cols - 1:
        out.append(_c('32', in_s, no_color) + '   ' +
                   _c('36', out_s.lstrip(), no_color) + '\033[K')
    else:
        out.append(_c('32', in_s, no_color) + '\033[K')
        out.append(_c('36', out_s, no_color) + '\033[K')
    out.append(_c('90', sep, no_color) + '\033[K')

    # Top sessions: show as many as the terminal allows while keeping gh >= 3.
    # Budget: lines - len(out) - 11  (11 = 2 graph labels + 2 baselines + 3*2 min rows + footer)
    avail = lines - len(out) - 11
    top_n = min(len(top_rates), max(0, avail - 2))   # -2 for header + sep
    if top_n > 0:
        out.append(_c('1', ' Top sessions by throughput:', no_color) + '\033[K')
        for ip, (ibps, obps) in top_rates[:top_n]:
            row = f"   {isg.long2ip(ip):<16} {_fmt_bps(ibps)} ↓  {_fmt_bps(obps)} ↑"
            out.append(row + '\033[K')
        out.append(_c('90', sep, no_color) + '\033[K')

    # Split remaining vertical space between the two graphs
    used = len(out) + 2 * 2 + 1   # 2 graph labels + 2 baselines + footer
    gh = max(3, (lines - used) // 2)

    out.append(_c('32', ' Incoming', no_color) + '\033[K')
    for row in _graph_block(in_hist, in_ceil, gw, gh, '32', no_color):
        out.append(row + '\033[K')

    out.append(_c('36', ' Outgoing', no_color) + '\033[K')
    for row in _graph_block(out_hist, out_ceil, gw, gh, '36', no_color):
        out.append(row + '\033[K')

    out.append(_c('90', footer, no_color) + '\033[K')
    out.append('\033[J')

    sys.stdout.write('\n'.join(out))
    sys.stdout.flush()
