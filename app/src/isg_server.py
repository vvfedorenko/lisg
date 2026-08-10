"""ISG session server — netlink event loop, auth/accounting dispatch."""
from __future__ import annotations

import logging
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from . import isg
from . import services as svc_mod
from .config import Config, Service
from .backends.base import AuthResult, Backend, BackendUnavailable, DynamicService

log = logging.getLogger(__name__)



class ISGServer:
    """
    Listens for ISG kernel events over Netlink and dispatches them to the
    configured auth/accounting backends.  Call run() from a daemon thread;
    signal stop via the threading.Event passed to the constructor.
    """

    def __init__(self, cfg: Config, nas_ip: str,
                 auth_pool: list[Backend], acct_pool: list[Backend],
                 stop: threading.Event):
        self._cfg       = cfg
        self._nas_ip    = nas_ip
        self._auth_pool = auth_pool
        self._acct_pool = acct_pool
        self._stop      = stop
        aw = cfg.auth_workers
        bw = cfg.acct_workers
        self._auth_nl      = isg.open_auth_socket()
        self._auth_nl_lock = threading.Lock()
        self._auth_pool_ex = (ThreadPoolExecutor(max_workers=aw, thread_name_prefix='auth')
                               if aw > 0 else None)
        self._acct_pool_ex = (ThreadPoolExecutor(max_workers=bw, thread_name_prefix='acct')
                              if bw > 0 else None)

    # ── public entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        sk = isg.open_socket()
        sk.settimeout(1.0)
        isg.send_only(sk, {'type': isg.EVENT_LISTENER_REG})

        auth_types = '+'.join(b.__class__.__name__.replace('Backend', '')
                              for b in self._auth_pool)
        acct_types = '+'.join(b.__class__.__name__.replace('Backend', '')
                              for b in self._acct_pool)
        log.info("ISG server ready, NAS='%s', auth=[%s], acct=[%s]",
                 self._nas_ip, auth_types, acct_types)

        while not self._stop.is_set():
            try:
                data = sk.recv(1500)
            except socket.timeout:
                continue
            except OSError as e:
                # A persistent error here (e.g. ENOBUFS when the kernel floods
                # session events and overruns SO_RCVBUF) must not turn into a
                # busy-loop that pins a core. Back off briefly before retrying.
                log.error('Netlink recv error: %s', e)
                self._stop.wait(0.1)
                continue

            try:
                self._dispatch(isg.parse_event(data))
            except ValueError as e:
                # Malformed/short netlink frame — skip it, keep the loop alive.
                log.warning('Skipping malformed netlink event: %s', e)
            except Exception:
                log.exception('Error dispatching netlink event')

        sk.close()
        if self._auth_pool_ex is not None:
            self._auth_pool_ex.shutdown(wait=False, cancel_futures=False)
        if self._acct_pool_ex is not None:
            self._acct_pool_ex.shutdown(wait=False, cancel_futures=False)

    # ── event dispatch ────────────────────────────────────────────────────────

    def _dispatch(self, ev: dict) -> None:
        t  = ev['type']
        ip = isg.long2ip(ev.get('ipaddr', 0))

        if t == isg.EVENT_SESS_CREATE:
            if self._auth_pool_ex is not None:
                if any(not b.is_circuit_open() for b in self._auth_pool):
                    self._auth_pool_ex.submit(self._auth_thread, ev)

        elif t in (isg.EVENT_SESS_START, isg.EVENT_SESS_UPDATE, isg.EVENT_SESS_STOP):
            if self._acct_pool_ex is not None and not (ev.get('flags', 0) & isg.NO_ACCT):
                if any(not b.is_circuit_open() for b in self._acct_pool):
                    self._acct_pool_ex.submit(self._acct_thread, ev)

            flags = ev.get('flags', 0)
            if flags & isg.IS_SERVICE and t == isg.EVENT_SESS_START:
                log.info("Service '%s' for '%s' started", ev.get('service_name'), ip)
            elif t == isg.EVENT_SESS_STOP:
                if flags & isg.IS_APPROVED_SESSION:
                    log.info("Session '%s' on Virtual%d finished",
                             ip, ev.get('port_number', 0))
                elif flags & isg.IS_SERVICE:
                    log.info("Service '%s' for '%s' finished",
                             ev.get('service_name'), ip)

    # ── worker threads ────────────────────────────────────────────────────────

    def _auth_thread(self, ev: dict) -> None:
        ip = isg.long2ip(ev.get('ipaddr', 0))

        result = None
        for backend in self._auth_pool:
            if backend.is_circuit_open():
                log.debug("Auth: skipping '%s' (circuit open)", backend.label)
                continue
            try:
                result = backend.authenticate(ev)
                break
            except BackendUnavailable as e:
                log.error("Auth backend unavailable for '%s': %s", ip, e)
        if result is None:
            log.error("All auth backends failed for '%s', session not approved", ip)
            return
        sk = self._auth_nl
        try:
            self._apply_auth_result(result, ev, sk)
        except OSError as e:
            log.error("Netlink error applying auth result for '%s': %s", ip, e)
            with self._auth_nl_lock:
                if self._auth_nl is sk:
                    self._auth_nl = isg.open_auth_socket()

    def _acct_thread(self, ev: dict) -> None:
        """All accounting backends receive the record (side by side)."""
        for backend in self._acct_pool:
            if backend.is_circuit_open():
                log.debug("Acct: skipping '%s' (circuit open)", backend.label)
                continue
            try:
                backend.account(ev)
            except BackendUnavailable as e:
                log.error('Acct backend unavailable: %s', e)
            except Exception as e:
                log.error('Accounting error: %s', e)

    # ── auth result application ───────────────────────────────────────────────

    def _apply_auth_result(self, result: AuthResult, ev: dict,
                           sk: socket.socket) -> None:
        port = ev.get('port_number', 0)
        ip   = isg.long2ip(ev.get('ipaddr', 0))

        # On reject, apply the configured walled-garden services — centrally,
        # for ANY auth backend (RADIUS, MySQL, …). Each entry is "A<name>"
        # (activate) or "N<name>" (deactivate).
        if not result.accept:
            for entry in (self._cfg.unauth_service_name_list or []):
                m = re.match(r'^(A|N)(.+)', str(entry))
                if m:
                    result.services.setdefault(m.group(2), m.group(1))

        # Register on-the-fly dynamic services with the kernel (in practice
        # only produced on accept; harmless when empty on reject).
        for ds in result.dynamic_services:
            if ds.name not in self._cfg.services:
                self._cfg.services[ds.name] = Service(
                    traffic_classes=[ds.traffic_class],
                    rate_info=ds.rate_info,
                )
                svc_mod.prepare(self._cfg, ds.name)
            isg.send_only(sk, {
                'type':           isg.EVENT_SDESC_ADD,
                'nehash_tc_name': ds.traffic_class,
                'service_name':   ds.name,
                'service_flags':  isg.SERVICE_DESC_IS_DYNAMIC,
            })
            result.services.setdefault(ds.name, 'A')

        # Resolve which services ACTUALLY apply (sanitize drops services that
        # are unknown / not prepared / class-conflicting).
        applied = svc_mod.sanitize(self._cfg, result.services)

        # A walled-garden service only counts as a real limiter if it actually
        # restricts traffic: either it polices (non-zero rate) or it is a
        # tagger (L4-redirect — traffic is diverted, not let onto the internet).
        # A policer with rate == 0 does NOT count: the kernel treats rate 0 as
        # "unlimited" (isg_main.c: `if (… || !rate) accept`), so approving on it
        # would hand a rejected user full-speed internet — the same fail-open
        # bug one level deeper.
        def _limits(name: str) -> bool:
            svc = self._cfg.services.get(name)
            return bool(svc and (svc.type == 'tagger' or svc.u_rate or svc.d_rate))

        has_active_service = any(st == 'A' and _limits(n) for n, st in applied.items())
        has_rate           = len(result.rate_info) == 4

        # FAIL-CLOSED: a rejected session is approved ONLY if a real limiter was
        # actually applied (an active walled-garden service, or an explicit
        # rate). If unauth_service_name_list is empty, misspelled, or its
        # service failed to prepare, `applied` is empty here — so we MUST NOT
        # approve, or the session would get full-speed internet with no shaper
        # (the long-standing fail-open bug). Left unapproved, the session keeps
        # flags == 0 and the kernel drops all its traffic
        # (isg_main.c: `if (!is->info.flags) goto drop`); we only cap how long
        # the dead session lingers before the kernel reaps and re-checks it.
        if not result.accept and not has_active_service and not has_rate:
            isg.send_only(sk, {
                'type':         isg.EVENT_SESS_CHANGE,
                'port_number':  port,
                'max_duration': self._cfg.unauth_session_max_duration,
            })
            log.debug("Session '%s' on Virtual%d rejected — no internet "
                      "(left unapproved)", ip, port)
            return

        # Apply the resolved services
        for svc_name, svc_status in applied.items():
            sev = svc_mod.build_event(self._cfg, svc_name)
            sev['type']        = isg.EVENT_SERV_APPLY
            sev['port_number'] = port
            if svc_status == 'A':
                sev['flags'] |= isg.SERVICE_STATUS_ON
            isg.send_only(sk, sev)

        # Approve / reject session
        cfg = self._cfg
        oev: dict = {
            'type':           isg.EVENT_SESS_APPROVE,
            'port_number':    port,
            'flags':          0,
            'alive_interval': (result.alive_interval
                               if result.alive_interval is not None
                               else cfg.session_alive_interval),
            'idle_timeout':   (result.idle_timeout
                               if result.idle_timeout is not None
                               else cfg.session_idle_timeout),
            'max_duration':   (result.max_duration
                               if (result.accept and result.max_duration is not None)
                               else (cfg.unauth_session_max_duration
                                     if not result.accept
                                     else cfg.session_max_duration)),
        }
        if result.cookie:
            oev['cookie'] = result.cookie
        if result.nat_ip:
            oev['nat_ipaddr'] = isg.ip2long(result.nat_ip)
        if len(result.rate_info) == 4:
            oev.update(in_rate=result.rate_info[0], in_burst=result.rate_info[1],
                       out_rate=result.rate_info[2], out_burst=result.rate_info[3])
        if cfg.no_accounting or result.no_accounting or not result.accept:
            oev['flags'] |= isg.NO_ACCT

        isg.send_only(sk, oev)
        log.info("Session '%s' on Virtual%d %s",
                 ip, port, 'accepted' if result.accept else 'rejected')
