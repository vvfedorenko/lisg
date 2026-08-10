"""MySQL backend — authenticates and accounts directly against a billing DB."""
from __future__ import annotations

import logging
import threading
import time

from .. import isg
from ..config import Config, ServerEntry
from .base import AuthResult, Backend, BackendUnavailable, apply_account_info

log = logging.getLogger(__name__)

try:
    import pymysql
    import pymysql.cursors
except ImportError:
    pymysql = None  # type: ignore

# MySQL CR_SERVER_GONE_ERROR / CR_SERVER_LOST — stale idle connection
_CONN_LOST = (2006, 2013)


class MySQLBackend(Backend):
    """
    Each worker thread gets its own DB connection (threading.local).
    Connection params come from the pool entry; query overrides from cfg.mysql.
    """

    def __init__(self, entry: ServerEntry, cfg: Config, nas_ip: str, nas_id: str):
        super().__init__()
        if pymysql is None:
            raise ImportError('pymysql required for MySQL backend: pip install pymysql')
        self._entry  = entry
        self._cfg    = cfg
        self._nas_ip = nas_ip
        self._nas_id = nas_id
        self._local  = threading.local()
        self.label   = f'mysql {entry.unix_socket or f"{entry.host}:{entry.port}"}'

    # ── DB connection ─────────────────────────────────────────────────────────

    def _conn(self):
        """Return a per-thread DB connection, recycling it when max age is reached."""
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            max_age = self._cfg.mysql.conn_max_age if self._cfg.mysql else 3600
            if time.monotonic() - getattr(self._local, 'conn_born', 0.0) >= max_age:
                log.debug('MySQL: recycling connection after %ds', max_age)
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
            self._local.conn_born = time.monotonic()
        return conn

    def _connect(self):
        e = self._entry
        kw = dict(
            user=e.user,
            password=e.password,
            database=e.database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
        if e.unix_socket:
            kw['unix_socket'] = e.unix_socket
        else:
            kw['host'] = e.host
            kw['port'] = e.port
        return pymysql.connect(**kw)

    # ── retry helper ──────────────────────────────────────────────────────────

    def _execute(self, fn, context: str):
        """Run fn(cursor) with one reconnect retry on lost-connection errors."""
        exc = None
        for attempt in range(2):
            try:
                with self._conn().cursor() as cur:
                    return fn(cur)
            except pymysql.err.OperationalError as e:
                self._local.conn = None
                exc = e
                if attempt == 0 and e.args[0] in _CONN_LOST:
                    log.info('MySQL %s: reconnecting after lost connection (%s)', context, e)
                    continue
                if attempt == 1:
                    log.warning('MySQL %s: reconnect did not help (%s)', context, e)
                break
        raise exc

    # ── public interface ──────────────────────────────────────────────────────

    def _query(self, key: str) -> str:
        """Return query from cfg.mysql override if set, else built-in default."""
        from .. import config as _cfg_mod
        defaults = {
            'auth_query':        _cfg_mod._DEFAULT_AUTH_QUERY,
            'acct_start_query':  _cfg_mod._DEFAULT_ACCT_START,
            'acct_update_query': _cfg_mod._DEFAULT_ACCT_UPDATE,
            'acct_stop_query':   _cfg_mod._DEFAULT_ACCT_STOP,
        }
        if self._cfg.mysql:
            return getattr(self._cfg.mysql, key, defaults[key])
        return defaults[key]

    def authenticate(self, ev: dict) -> AuthResult:
        ip = isg.long2ip(ev.get('ipaddr', 0))
        try:
            def _q(cur):
                cur.execute(self._query('auth_query'), {'ip': ip, 'nas_ip': self._nas_ip})
                return cur.fetchone()
            row = self._execute(_q, 'auth')
        except pymysql.err.OperationalError as e:
            self.record_err()
            raise BackendUnavailable(f'MySQL auth error for {ip}: {e}')

        self.record_ok()
        if not row:
            log.debug("MySQL: no record for '%s', rejecting", ip)
            return AuthResult(accept=False)

        return self._row_to_result(row)

    def account(self, ev: dict) -> None:
        evt = ev.get('type')
        params = {
            'session_id':   ev.get('session_id', ''),
            'ip':           isg.long2ip(ev.get('ipaddr', 0)),
            'nat_ip':       isg.long2ip(ev.get('nat_ipaddr', 0)),
            'port_number':  ev.get('port_number', 0),
            'duration':     ev.get('duration', 0),
            'in_bytes':     ev.get('in_bytes', 0),
            'out_bytes':    ev.get('out_bytes', 0),
            'in_packets':   ev.get('in_packets', 0),
            'out_packets':  ev.get('out_packets', 0),
            'service_name': ev.get('service_name') or '',
            'nas_ip':       self._nas_ip,
            'nas_id':       self._nas_id,
        }

        acct_type_map = {
            isg.EVENT_SESS_START:  ('Start', self._query('acct_start_query')),
            isg.EVENT_SESS_UPDATE: ('Alive', self._query('acct_update_query')),
            isg.EVENT_SESS_STOP:   ('Stop',  self._query('acct_stop_query')),
        }
        type_name, query = acct_type_map.get(evt, ('Unknown', ''))
        if not query:
            return
        params['acct_type'] = type_name

        try:
            self._execute(lambda cur: cur.execute(query, params), 'acct')
            self.record_ok()
        except pymysql.err.OperationalError as e:
            log.error('MySQL acct error (%s) for %s: %s', type_name, params['ip'], e)
            self.record_err()

    def close(self) -> None:
        conn = getattr(self._local, 'conn', None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    # ── result parsing ────────────────────────────────────────────────────────

    def _row_to_result(self, row: dict) -> AuthResult:
        """
        Map a DB result row to AuthResult.

        Recognised columns (all optional; a non-empty row implies accept=True):
          accepted             — 0/1; absent = accepted
          cisco-avpair         — Cisco-Account-Info string(s), comma-separated.
                                 Parsed identically to RADIUS Cisco-Account-Info:
                                   A<name> / N<name>  — activate/deactivate service
                                   QD;<dl>;…;U;<ul>;… — session rate
                                   QC;<class>;…       — dynamic per-class service
          nat_ip               — Framed-IP-Address (string IPv4)
          alive_interval       — Acct-Interim-Interval (integer seconds)
          max_duration         — Session-Timeout (integer seconds)
          idle_timeout         — Idle-Timeout (integer seconds)
          class / cookie       — Class attribute (≤32 chars)
          no_accounting        — 0/1
        """
        if not row.get('accepted', 1):
            return AuthResult(accept=False)

        result = AuthResult(accept=True)

        # ── Cisco-Account-Info (cisco-avpair column, comma-separated) ─────────
        # Accepts column names: cisco-avpair, cisco_avpair, cisco_account_info
        cai = (row.get('cisco-avpair') or
               row.get('cisco_avpair') or
               row.get('cisco_account_info') or '')
        if cai:
            apply_account_info(result, str(cai).split(','))

        # ── standard session columns ──────────────────────────────────────────
        nat = row.get('nat_ip')
        if nat:
            result.nat_ip = str(nat)

        for col, attr in (('alive_interval', 'alive_interval'),
                           ('max_duration',   'max_duration'),
                           ('idle_timeout',   'idle_timeout')):
            v = row.get(col)
            if v is not None:
                setattr(result, attr, int(v))

        cls_val = row.get('class') or row.get('cookie')
        if cls_val:
            result.cookie = str(cls_val)[:32]

        if row.get('no_accounting'):
            result.no_accounting = True

        return result
