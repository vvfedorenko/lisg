#!/usr/bin/env python3
"""ISGd — ISG daemon."""
from __future__ import annotations
import argparse
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from src import isg
from src import services as svc_mod
from src import tc as tc_mod
from src.coa_server import CoAServer
from src.isg_server import ISGServer
from src.api import APIServer
from src.api.server import APIContext
from src.config import Config, load as load_config
from src.backends.base import Backend

try:
    from pyrad.dictionary import Dictionary as RadDict
except ImportError:
    sys.exit('pyrad required: pip install pyrad')


# ─── pool factory ────────────────────────────────────────────────────────────

def _make_pool(cfg: Config, section: dict,
               nas_ip: str, nas_id: str,
               rad_dict: RadDict, log) -> list[Backend]:
    """Build an ordered list of backends from an auth or accounting pool dict."""
    pool: list[Backend] = []
    for prio in sorted(section):
        entry = section[prio]
        if entry.type == 'radius':
            from src.backends.radius import RadiusBackend
            pool.append(RadiusBackend(entry, cfg, nas_ip, nas_id, rad_dict))
        elif entry.type == 'mysql':
            if not (entry.host or entry.unix_socket):
                log.error('Pool entry %d type=mysql requires host (or unix_socket) + user/password/database', prio)
                continue
            from src.backends.mysql import MySQLBackend
            pool.append(MySQLBackend(entry, cfg, nas_ip, nas_id))
        else:
            log.error("Unknown backend type '%s' at priority %d", entry.type, prio)
    return pool


# ─── daemon class ─────────────────────────────────────────────────────────────

class Daemon:
    def __init__(self, cfg: Config):
        self.cfg      = cfg
        self.nas_ip   = cfg.nas_ip or isg.get_nas_ip() or '127.0.0.1'
        self.nas_id   = cfg.nas_identifier or self.nas_ip
        self.rad_dict = self._load_dict()
        log = logging.getLogger('ISGd')
        self._auth_pool  = _make_pool(cfg, cfg.auth,       self.nas_ip, self.nas_id,
                                      self.rad_dict, log)
        self._acct_pool  = _make_pool(cfg, cfg.accounting, self.nas_ip, self.nas_id,
                                      self.rad_dict, log)
        self._stop    = threading.Event()
        self._coa          = CoAServer(cfg, self.nas_ip, self.nas_id,
                                       self.rad_dict, self._stop)
        self._isg = ISGServer(cfg, self.nas_ip,
                              self._auth_pool, self._acct_pool,
                              self._stop)
        self._api = APIServer(
            APIContext(cfg=cfg, nas_ip=self.nas_ip,
                       auth_pool=self._auth_pool, acct_pool=self._acct_pool),
            self._stop,
        ) if cfg.api else None
        self._log     = logging.getLogger('ISGd')

    # ── setup ─────────────────────────────────────────────────────────────────

    def _load_dict(self) -> RadDict:
        d = RadDict(self.cfg.radius_dictionary)
        cisco = self.cfg.radius_dictionary + '.cisco'
        if os.path.isfile(cisco):
            d.ReadDictionary(cisco)
        return d

    def _setup_logging(self):
        if self.cfg.daemonize:
            facility = logging.handlers.SysLogHandler.facility_names.get(
                self.cfg.log_facility.lower(),
                logging.handlers.SysLogHandler.LOG_LOCAL7
            )
            h = logging.handlers.SysLogHandler(address='/dev/log', facility=facility)
        else:
            h = logging.StreamHandler(sys.stdout)
        root = logging.getLogger()
        root.addHandler(h)
        root.setLevel(logging.DEBUG if self.cfg.debug else logging.INFO)

    def _check_pid(self):
        pid_file = self.cfg.pid_file
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                if os.path.exists(f'/proc/{pid}/stat'):
                    sys.exit(f'ISGd already running (PID {pid})')
            except (ValueError, OSError):
                pass

    def _write_pid(self):
        with open(self.cfg.pid_file, 'w') as f:
            f.write(str(os.getpid()))

    def _daemonize(self):
        if os.fork():
            os._exit(0)
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if os.fork():
            os._exit(0)
        os.chdir('/')
        os.umask(0)
        self._write_pid()
        log_path = '/tmp/ISGd_dbg.log' if self.cfg.debug else '/dev/null'
        fd = os.open(log_path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
        for fileno in (sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()):
            os.dup2(fd, fileno)
        if fd > 2:
            os.close(fd)

    # ── startup ───────────────────────────────────────────────────────────────

    def _init_kernel(self):
        for name in list(self.cfg.services):
            svc_mod.prepare(self.cfg, name)

        tc_names: dict = {}
        tc_mod.reload(self.cfg, collect=tc_names)

        sk = isg.open_socket()
        try:
            isg.send_event(sk, {'type': isg.EVENT_SDESC_SWEEP_TC})
            for tc_name in tc_names:
                for svc_name, svc in self.cfg.services.items():
                    if tc_name in svc.traffic_classes:
                        isg.send_event(sk, {
                            'type':           isg.EVENT_SDESC_ADD,
                            'nehash_tc_name': tc_name,
                            'service_name':   svc_name,
                        })
        except OSError as e:
            sys.exit(f'Startup netlink error: {e}')
        finally:
            sk.close()

    # ── jobs ─────────────────────────────────────────────────────────────────

    def job_status(self, interval: float = 5.0):
        path = os.path.splitext(self.cfg.pid_file)[0] + '.status'
        tmp  = path + '.tmp'
        while not self._stop.is_set():
            data = {
                'written_at': time.time(),
                'auth': [b.status_dict() for b in self._auth_pool],
                'acct': [b.status_dict() for b in self._acct_pool],
            }
            try:
                with open(tmp, 'w') as f:
                    json.dump(data, f)
                os.replace(tmp, path)
            except OSError:
                pass
            self._stop.wait(interval)
        try:
            os.unlink(path)
        except OSError:
            pass

    def job_reload_tc(self):
        prev = tc_mod.reload(self.cfg)
        while not self._stop.is_set():
            self._stop.wait(self.cfg.tc_check_interval)
            result = tc_mod.reload(self.cfg, prev_md5=prev)
            if result:
                prev = result

    def job_coa(self):
        self._coa.run()

    def job_isg(self):
        self._isg.run()

    # ── run ───────────────────────────────────────────────────────────────────

    def run(self):
        self._setup_logging()
        self._check_pid()
        self._init_kernel()

        if self.cfg.daemonize:
            self._daemonize()

        def _shutdown(sig, _):
            self._log.info('Signal %d received, shutting down', sig)
            self._stop.set()
            try:
                os.unlink(self.cfg.pid_file)
            except OSError:
                pass

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        if not self.cfg.daemonize:
            self._write_pid()

        threads = [
            threading.Thread(target=self.job_isg,       name='ISG',        daemon=True),
            threading.Thread(target=self.job_coa,        name='CoA',        daemon=True),
            threading.Thread(target=self.job_reload_tc,  name='TC_Refresh', daemon=True),
            threading.Thread(target=self.job_status,     name='Status',     daemon=True),
        ]
        if self._api:
            threads.append(
                threading.Thread(target=self._api.run, name='API', daemon=True)
            )
        for t in threads:
            t.start()
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self._stop.set()
        finally:
            for b in self._auth_pool + self._acct_pool:
                b.close()
        for t in threads:
            t.join(timeout=5.0)


# ─── entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='ISG daemon')
    parser.add_argument(
        '--conf',
        default=os.path.join(os.path.dirname(__file__), 'config.yaml'),
        help='Path to YAML config (default: ./config.yaml)')
    args = parser.parse_args()
    Daemon(load_config(args.conf)).run()


if __name__ == '__main__':
    main()
