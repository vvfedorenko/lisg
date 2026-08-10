"""Server-Sent Events stream for real-time per-session traffic.

Yields SSE 'data:' lines; each event is a JSON object:
  {"ts": <unix float>, "sessions": [
    {"ip": "...", "session_id": "...",
     "in_bps": <int>, "out_bps": <int>,
     "in_bytes": <int>, "out_bytes": <int>}
  ]}

Rates are computed as (byte_delta * 8) / elapsed from cumulative kernel
counters.  The first event always has in_bps / out_bps == 0.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator

from . import sessions as sess

_KEEPALIVE_INTERVAL = 15.0


async def traffic_stream(
    id_str: str,
    interval: float,
) -> AsyncGenerator[str, None]:
    prev: dict[str, tuple[int, int, float]] = {}
    next_keepalive = time.monotonic() + _KEEPALIVE_INTERVAL

    while True:
        t0 = time.monotonic()

        raw = await asyncio.to_thread(sess.find_session, id_str)
        rows = [raw] if raw else []

        ts = time.time()
        result = []
        for s in rows:
            sid = s['session_id']
            ib, ob = s['in_bytes'], s['out_bytes']
            if sid in prev:
                prev_ib, prev_ob, prev_ts = prev[sid]
                elapsed = ts - prev_ts
                if elapsed > 0:
                    in_bps  = max(0, int((ib - prev_ib) * 8 / elapsed))
                    out_bps = max(0, int((ob - prev_ob) * 8 / elapsed))
                else:
                    in_bps = out_bps = 0
            else:
                in_bps = out_bps = 0
            prev[sid] = (ib, ob, ts)
            result.append({
                'ip':         s['ip'],
                'session_id': sid,
                'in_bps':     in_bps,
                'out_bps':    out_bps,
                'in_bytes':   ib,
                'out_bytes':  ob,
            })

        if not rows:
            prev.clear()

        yield f'data: {json.dumps({"ts": ts, "sessions": result})}\n\n'
        next_keepalive = time.monotonic() + _KEEPALIVE_INTERVAL

        sleep_for = max(0.0, interval - (time.monotonic() - t0))
        await asyncio.sleep(sleep_for)

        if time.monotonic() >= next_keepalive:
            yield ': keepalive\n\n'
            next_keepalive = time.monotonic() + _KEEPALIVE_INTERVAL
