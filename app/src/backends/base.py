"""Abstract backend interface for authentication and accounting.

BackendUnavailable — raised when a backend cannot be reached (timeout, network
error, DB down, …).  The caller should catch it and try the next entry in the
pool rather than treating the session as rejected.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


class BackendUnavailable(Exception):
    """Backend could not be reached — caller should try the next pool entry."""


@dataclass
class DynamicService:
    """A per-session service created on-the-fly from RADIUS/DB response."""
    name: str           # computed identifier, e.g. DYN_<md5>
    traffic_class: str  # TC table class name
    rate_info: str      # Cisco-Account-Info string used to derive rates


@dataclass
class AuthResult:
    """Normalised result returned by Backend.authenticate()."""
    accept: bool = False

    # Session parameters (None = use daemon config defaults)
    nat_ip:         Optional[str] = None
    alive_interval: Optional[int] = None
    max_duration:   Optional[int] = None
    idle_timeout:   Optional[int] = None
    cookie:         Optional[str] = None
    no_accounting:  bool = False

    # Rate override (list of 4 ints: ul_rate, ul_burst, dl_rate, dl_burst)
    rate_info: list = field(default_factory=list)

    # Named services to activate/deactivate: {'SVC': 'A'} or {'SVC': 'N'}
    services: dict = field(default_factory=dict)

    # On-the-fly services declared by the backend (RADIUS QC; or DB rows)
    dynamic_services: list = field(default_factory=list)


def apply_account_info(result: AuthResult, values: list) -> None:
    """
    Parse Cisco-Account-Info value strings into an AuthResult.

    Shared by every backend (RADIUS attributes, MySQL column, …) so the
    interpretation is identical no matter where the values come from:

      A<name> / N<name>  — activate / deactivate a named service
      QC;<class>;…       — on-the-fly per-class dynamic service
      Q…  (QD/QU/…)      — session rate override (Cisco QoS string)
    """
    from .. import services as svc_mod   # local import avoids any import cycle
    for raw in values:
        val = str(raw).strip()
        if not val:
            continue
        m = re.match(r'^(A|N)(.+)', val)
        if m:
            result.services[m.group(2)] = m.group(1)
        elif re.match(r'^QC;', val, re.I):
            m2 = re.match(r'^QC;([^;]+)', val, re.I)
            if m2:
                dyn = 'DYN_' + hashlib.md5(val.encode()).hexdigest()[:16].upper()
                result.dynamic_services.append(
                    DynamicService(name=dyn, traffic_class=m2.group(1), rate_info=val))
        elif val.upper().startswith('Q'):
            parsed = svc_mod.parse_qos(val)
            if len(parsed) == 4:
                result.rate_info = parsed
        else:
            log.error("Unknown Cisco-Account-Info value '%s'", val)


_CB_THRESHOLD = 3    # consecutive errors before opening circuit
_CB_PENALTY   = 30   # seconds to stay open before one retry is allowed
_RATE_WINDOW  = 60.0 # sliding window width for req/s calculation


class RateCounter:
    """Two-bucket sliding window rate counter (events/s over last 60 s)."""

    __slots__ = ('_curr', '_prev', '_ts')

    def __init__(self):
        self._curr = 0
        self._prev = 0
        self._ts   = 0.0

    def tick(self) -> None:
        now = time.monotonic()
        if self._ts == 0.0:
            self._ts = now
        elif now - self._ts >= _RATE_WINDOW:
            self._prev = self._curr
            self._curr = 0
            self._ts   = now
        self._curr += 1

    @property
    def value(self) -> float:
        now = time.monotonic()
        if self._ts == 0.0:
            return 0.0
        elapsed_curr = min(now - self._ts, _RATE_WINDOW)
        prev_weight  = 1.0 - elapsed_curr / _RATE_WINDOW
        return round((self._prev * prev_weight + self._curr) / _RATE_WINDOW, 2)


@dataclass
class BackendStats:
    label:            str
    ok:               int
    err:              int
    success_rate:     float
    error_rate:       float
    total_rate:       float
    last_ok_ago:      Optional[float]
    last_err_ago:     Optional[float]
    circuit_open:     bool
    circuit_open_for: Optional[float]

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


class Backend(ABC):
    """
    All authentication and accounting goes through this interface.

    authenticate() is called once per new session (EVENT_SESS_CREATE).
    account()      is called for Start / Interim / Stop events.
    Both methods are invoked from worker threads and MUST be thread-safe.
    """

    def __init__(self):
        self.label        = ''
        self.ok_count     = 0
        self.err_count    = 0
        self._last_ok_t   = 0.0   # time.monotonic() of last success
        self._last_err_t  = 0.0   # time.monotonic() of last error
        self._consec_err  = 0     # consecutive errors; reset on success
        self._open_until  = 0.0   # circuit open until this monotonic time
        self._ok_rate     = RateCounter()
        self._err_rate    = RateCounter()
        self._total_rate  = RateCounter()

    def _record(self, success: bool) -> None:
        now = time.monotonic()
        self._total_rate.tick()
        if success:
            self.ok_count    += 1
            self._last_ok_t   = now
            self._consec_err  = 0
            self._ok_rate.tick()
        else:
            self.err_count   += 1
            self._last_err_t  = now
            self._consec_err += 1
            self._err_rate.tick()
            if self._consec_err >= _CB_THRESHOLD:
                just_opened = now >= self._open_until
                self._open_until = now + _CB_PENALTY
                if just_opened:
                    log.warning("Backend '%s' circuit opened — skipping for %ds",
                                self.label, _CB_PENALTY)

    def record_ok(self) -> None:
        self._record(True)

    def record_err(self) -> None:
        self._record(False)

    def is_circuit_open(self) -> bool:
        if self._open_until and time.monotonic() >= self._open_until:
            # Penalty expired: fresh start — next request is the probe.
            self._open_until = 0.0
            self._consec_err = 0
        return self._open_until > 0

    def get_stats(self) -> BackendStats:
        now      = time.monotonic()
        open_for = max(0.0, self._open_until - now)
        return BackendStats(
            label            = self.label,
            ok               = self.ok_count,
            err              = self.err_count,
            success_rate     = self._ok_rate.value,
            error_rate       = self._err_rate.value,
            total_rate       = self._total_rate.value,
            last_ok_ago      = round(now - self._last_ok_t,  1) if self._last_ok_t  else None,
            last_err_ago     = round(now - self._last_err_t, 1) if self._last_err_t else None,
            circuit_open     = open_for > 0,
            circuit_open_for = round(open_for, 1) if open_for > 0 else None,
        )

    def status_dict(self) -> dict:
        return self.get_stats().to_dict()

    @abstractmethod
    def authenticate(self, ev: dict) -> AuthResult:
        """Synchronously authenticate a session. Block until result or timeout."""

    @abstractmethod
    def account(self, ev: dict) -> None:
        """Send an accounting record. May be fire-and-forget."""

    def close(self) -> None:
        """Release any persistent resources (DB connections, sockets, …)."""
