"""Service lifecycle: rate parsing, validation, event building, conflict resolution."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from .config import Config, Service
from . import isg

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


def parse_qos(rate_str: str) -> list[int]:
    """
    Parse a Cisco-Account-Info QoS string.
    Returns [ul_rate, ul_burst, dl_rate, dl_burst] in kbps, or [].
    """
    ret = []
    m = re.search(r'U;(\d+);(\d+)', rate_str)
    if m:
        ret += [int(m.group(1)), int(m.group(2)) * 8]
    m = re.search(r'D;(\d+);(\d+)', rate_str)
    if m:
        ret += [int(m.group(1)), int(m.group(2)) * 8]
    return ret


def prepare(cfg: Config, name: str) -> bool:
    """
    Validate service config and compute rate fields in-place.
    Removes the service from cfg.services and returns False if invalid.
    """
    svc = cfg.services.get(name)
    if svc is None:
        return False

    if not svc.traffic_classes:
        log.error("Service '%s' has no traffic_classes — discarding", name)
        del cfg.services[name]
        return False

    if svc.rate_info:
        rates = parse_qos(svc.rate_info)
        if len(rates) != 4:
            log.error("Bad rate_info for service '%s' — discarding", name)
            del cfg.services[name]
            return False
        svc.u_rate, svc.u_burst, svc.d_rate, svc.d_burst = rates

    svc.alive_interval = svc.alive_interval if svc.alive_interval is not None \
        else cfg.session_alive_interval
    svc.idle_timeout   = svc.idle_timeout   if svc.idle_timeout   is not None \
        else cfg.session_idle_timeout
    svc.max_duration   = svc.max_duration   if svc.max_duration   is not None \
        else cfg.session_max_duration
    return True


def build_event(cfg: Config, name: str) -> dict:
    """Return an ISG event dict pre-filled from the service definition."""
    svc = cfg.services[name]
    flags = 0
    if svc.no_accounting:
        flags |= isg.NO_ACCT
    if svc.type == 'tagger':
        flags |= isg.SERVICE_TAGGER | isg.NO_ACCT
    return {
        'service_name':   name,
        'out_rate':       svc.d_rate,
        'out_burst':      svc.d_burst,
        'in_rate':        svc.u_rate,
        'in_burst':       svc.u_burst,
        'alive_interval': svc.alive_interval,
        'idle_timeout':   svc.idle_timeout,
        'max_duration':   svc.max_duration,
        'flags':          flags,
    }


def sanitize(cfg: Config, srv_list: dict[str, str]) -> dict[str, str]:
    """
    Resolve traffic-class conflicts between simultaneously active services.
    Returns a cleaned {name: 'A'|'N'} dict.
    """
    on_cls: dict[str, dict[str, str]] = {}   # {svc_type: {class: first_owner}}
    ret:    dict[str, str]             = {}

    for name, status in srv_list.items():
        if name not in cfg.services:
            log.warning("Service '%s' not in config — ignoring", name)
            continue
        ret[name] = 'N'
        if status != 'A':
            continue
        svc = cfg.services[name]
        overlap = False
        for cls in svc.traffic_classes:
            owner = on_cls.get(svc.type, {}).get(cls)
            if owner:
                log.warning("Service '%s' shares class '%s' with '%s' — disabling both",
                            name, cls, owner)
                ret[owner] = ret[name] = 'N'
                overlap = True
                break
        if not overlap:
            ret[name] = 'A'
            on_cls.setdefault(svc.type, {})
            for cls in svc.traffic_classes:
                on_cls[svc.type][cls] = name

    return ret
