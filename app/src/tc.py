"""Traffic classification table: parse tc.conf, push to kernel via netlink."""
from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import Optional

from .config import Config
from . import isg

log = logging.getLogger(__name__)


def reload(cfg: Config,
           prev_md5: Optional[bytes] = None,
           collect: Optional[dict] = None) -> Optional[bytes]:
    """
    Load (or reload on change) tc.conf into the kernel nehash table.

    Returns the file's MD5 digest when the table was (re)loaded, None otherwise.
    If *collect* is provided it is populated with {class_name: ref_count}.
    """
    if not os.path.isfile(cfg.tc_file):
        log.warning("tc_file not found: %s", cfg.tc_file)
        return None

    with open(cfg.tc_file, 'rb') as f:
        content = f.read()

    curr_md5 = hashlib.md5(content).digest()
    if prev_md5 is not None and curr_md5 == prev_md5:
        return None

    pfx: dict[tuple[int, int], str] = {}   # {(net, mask): class_name}

    for line in content.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([^#\s]\S*)\s+(\S+)/(\d{1,2})$', line)
        if not m:
            log.error("Bad line in tc.conf: '%s'", line)
            return None
        cls, net_str, plen = m.group(1), m.group(2), int(m.group(3))
        if plen > 32:
            log.error("Prefix length > 32 in tc.conf: '%s/%d'", net_str, plen)
            return None
        mask    = (~((1 << (32 - plen)) - 1)) & 0xFFFFFFFF if plen else 0
        net_int = isg.ip2long(net_str)
        if net_int & ~mask:
            log.error("Host bits set in tc.conf prefix: '%s/%d'", net_str, plen)
            return None
        key = (net_int, mask)
        if key in pfx:
            log.error("Duplicate prefix '%s/%d' in tc.conf", net_str, plen)
            return None
        pfx[key] = cls
        if collect is not None:
            collect[cls] = collect.get(cls, 0) + 1

    sk = isg.open_socket()
    try:
        log.info("Refreshing traffic classification table")
        isg.send_event(sk, {'type': isg.EVENT_NE_SWEEP_QUEUE})
        for (net_int, mask_int), cls in pfx.items():
            isg.send_event(sk, {
                'type':           isg.EVENT_NE_ADD_QUEUE,
                'nehash_pfx':     net_int,
                'nehash_mask':    mask_int,
                'nehash_tc_name': cls,
            })
        isg.send_event(sk, {'type': isg.EVENT_NE_COMMIT})
    except OSError as e:
        log.error("TC reload netlink error: %s", e)
        sk.close()
        return None

    sk.close()
    log.info("%d prefixes loaded", len(pfx))
    return curr_md5
