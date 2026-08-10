"""Configuration: YAML → typed Config dataclass."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

_DEFAULT_AUTH_QUERY = (
    "SELECT 1 AS accepted, `cisco-avpair` "
    "FROM radius_clients WHERE ip = %(ip)s LIMIT 1"
)
_DEFAULT_ACCT_START = (
    "INSERT INTO radacct "
    "(acctsessionid, username, nasipaddress, nasportid, acctstarttime, framedipaddress) "
    "VALUES (%(session_id)s, %(ip)s, %(nas_ip)s, %(port_number)s, NOW(), %(nat_ip)s) "
    "ON DUPLICATE KEY UPDATE acctstarttime = NOW()"
)
_DEFAULT_ACCT_UPDATE = (
    "UPDATE radacct SET acctsessiontime = %(duration)s, "
    "acctinputoctets = %(in_bytes)s, acctoutputoctets = %(out_bytes)s "
    "WHERE acctsessionid = %(session_id)s"
)
_DEFAULT_ACCT_STOP = (
    "UPDATE radacct SET acctstoptime = NOW(), "
    "acctsessiontime = %(duration)s, "
    "acctinputoctets = %(in_bytes)s, acctoutputoctets = %(out_bytes)s "
    "WHERE acctsessionid = %(session_id)s"
)


@dataclass
class ServerEntry:
    """One entry in the auth or accounting pool."""
    type:    str   = 'radius'   # 'radius' | 'mysql'

    # RADIUS-specific
    server:  str   = ''
    secret:  bytes = b''
    timeout: int   = 5

    # MySQL connection (per-entry; allows different DB servers for auth/acct)
    host:        str = ''
    port:        int = 3306
    unix_socket: str = ''   # if set, used instead of host:port
    user:        str = ''
    password:    str = ''
    database:    str = ''

    def host_port(self) -> tuple[str, int]:
        host, _, port = self.server.rpartition(':')
        return (host or self.server), int(port or 1812)


@dataclass
class APIConfig:
    enabled:     bool      = True
    host:        str       = '0.0.0.0'
    port:        int       = 8080
    token:       str       = ''
    access_list: list[str] = field(default_factory=list)


@dataclass
class MySQLConfig:
    """Query overrides shared by all mysql-type pool entries."""
    auth_query:        str = _DEFAULT_AUTH_QUERY
    acct_start_query:  str = _DEFAULT_ACCT_START
    acct_update_query: str = _DEFAULT_ACCT_UPDATE
    acct_stop_query:   str = _DEFAULT_ACCT_STOP
    conn_max_age:      int = 3600


@dataclass
class Service:
    traffic_classes: list[str]
    rate_info: str          = ''
    type: str               = 'policer'
    no_accounting: bool     = False
    alive_interval: Optional[int] = None
    idle_timeout:   Optional[int] = None
    max_duration:   Optional[int] = None
    u_rate:  int = 0
    u_burst: int = 0
    d_rate:  int = 0
    d_burst: int = 0


@dataclass
class Config:
    # required
    radius_dictionary: str
    tc_file:           str

    # daemon
    daemonize:    bool = True
    debug:        bool = False
    log_facility: str  = 'local7'
    pid_file:     str  = '/var/run/ISGd.pid'

    # NAS identity
    nas_ip:         Optional[str] = None
    nas_identifier: Optional[str] = None

    # Auth and accounting pools — each entry specifies its own type
    # {priority: ServerEntry}; tried in ascending priority order.
    # Auth:       first entry that returns a result wins.
    # Accounting: all entries are called (side by side).
    auth:       dict[int, ServerEntry] = field(default_factory=dict)
    accounting: dict[int, ServerEntry] = field(default_factory=dict)

    # MySQL query overrides (shared by all type=mysql entries; connection params are per-entry)
    mysql: Optional[MySQLConfig] = None

    # REST API (optional)
    api: Optional[APIConfig] = None

    # CoA (always RADIUS)
    coa_secret: bytes        = b''
    coa_port:   int          = 3799
    coa_server: Optional[str] = None

    # session defaults
    session_alive_interval:      int = 60
    session_idle_timeout:        int = 1800
    session_max_duration:        int = 86400
    unauth_session_max_duration: int = 60
    unauth_service_name_list:    list[str] = field(default_factory=list)
    no_accounting:               bool = False
    no_color_output:             bool = False
    tc_check_interval:           int  = 300
    auth_workers:                int  = 16   # 0 = disable auth entirely
    acct_workers:                int  = 32   # 0 = disable accounting entirely

    services: dict[str, Service] = field(default_factory=dict)


# ─── loader ───────────────────────────────────────────────────────────────────

def load(path: str) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)

    base = os.path.dirname(os.path.abspath(path))

    def resolve(p: str) -> str:
        return p if os.path.isabs(p) else os.path.join(base, p)

    def to_bytes(s) -> bytes:
        return s.encode() if isinstance(s, str) else (s or b'')

    def parse_pool(section) -> dict[int, ServerEntry]:
        result = {}
        for prio, entry in (section or {}).items():
            t = entry.get('type', 'radius')
            result[int(prio)] = ServerEntry(
                type=t,
                server=entry.get('server', ''),
                secret=to_bytes(entry.get('secret', '')),
                timeout=int(entry.get('timeout', 5)),
                host=entry.get('host', ''),
                port=int(entry.get('port', 3306)),
                unix_socket=entry.get('unix_socket', ''),
                user=entry.get('user', ''),
                password=str(entry.get('password', '')),
                database=entry.get('database', ''),
            )
        return result

    def parse_api(section) -> Optional[APIConfig]:
        if not section:
            return None
        if not section.get('enabled', True):
            return None
        return APIConfig(
            enabled=True,
            host=section.get('host', '0.0.0.0'),
            port=int(section.get('port', 8080)),
            token=str(section.get('token', '')),
            access_list=list(section.get('access_list') or []),
        )

    def parse_mysql(section) -> Optional[MySQLConfig]:
        if not section:
            return None
        return MySQLConfig(
            auth_query=section.get('auth_query', _DEFAULT_AUTH_QUERY),
            acct_start_query=section.get('acct_start_query', _DEFAULT_ACCT_START),
            acct_update_query=section.get('acct_update_query', _DEFAULT_ACCT_UPDATE),
            acct_stop_query=section.get('acct_stop_query', _DEFAULT_ACCT_STOP),
            conn_max_age=int(section.get('conn_max_age', 3600)),
        )

    services = {}
    for name, svc in (raw.get('services') or {}).items():
        services[name] = Service(
            traffic_classes=list(svc.get('traffic_classes') or []),
            rate_info=svc.get('rate_info', ''),
            type=svc.get('type', 'policer'),
            no_accounting=bool(svc.get('no_accounting', False)),
            alive_interval=svc.get('alive_interval'),
            idle_timeout=svc.get('idle_timeout'),
            max_duration=svc.get('max_duration'),
        )

    return Config(
        radius_dictionary=resolve(raw.get('radius_dictionary', 'raddb/dictionary')),
        tc_file=resolve(raw.get('tc_file', 'tc.conf')),
        pid_file=raw.get('pid_file', '/var/run/ISGd.pid'),
        daemonize=bool(raw.get('daemonize', True)),
        debug=bool(raw.get('debug', False)),
        log_facility=raw.get('log_facility', 'local7'),
        nas_ip=raw.get('nas_ip'),
        nas_identifier=raw.get('nas_identifier'),
        auth=parse_pool(raw.get('auth')),
        accounting=parse_pool(raw.get('accounting')),
        mysql=parse_mysql(raw.get('mysql')),
        api=parse_api(raw.get('api')),
        coa_secret=to_bytes(raw.get('coa_secret', '')),
        coa_port=int(raw.get('coa_port', 3799)),
        coa_server=raw.get('coa_server'),
        session_alive_interval=int(raw.get('session_alive_interval', 60)),
        session_idle_timeout=int(raw.get('session_idle_timeout', 1800)),
        session_max_duration=int(raw.get('session_max_duration', 86400)),
        unauth_session_max_duration=int(raw.get('unauth_session_max_duration', 60)),
        unauth_service_name_list=list(raw.get('unauth_service_name_list') or []),
        no_accounting=bool(raw.get('no_accounting', False)),
        no_color_output=bool(raw.get('no_color_output', False)),
        tc_check_interval=int(raw.get('tc_check_interval', 300)),
        auth_workers=int(raw.get('auth_workers', 16)),
        acct_workers=int(raw.get('acct_workers', 32)),
        services=services,
    )
