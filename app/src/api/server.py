"""API server and shared context.

FastAPI/uvicorn are imported lazily (inside create_app / run) so that ISGd can
start without those packages installed when the API is disabled.

NOTE: this module deliberately does NOT use ``from __future__ import annotations``.
The endpoint type hints (e.g. ``upd: SessionUpdate``) must resolve to real
objects at function-definition time, because the models are imported locally
inside ``create_app`` and would otherwise be invisible to FastAPI's
``get_type_hints`` (which only sees module globals).
"""
import asyncio
import logging
import re
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ── API context (shared state) ────────────────────────────────────────────────

@dataclass
class APIContext:
    cfg:        object  # Config (avoid import cycle / typing at runtime)
    nas_ip:     str
    auth_pool:  list
    acct_pool:  list
    started_at: float = field(default_factory=time.monotonic)


def _is_ip(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))


# ── FastAPI app factory (lazy imports) ────────────────────────────────────────

def create_app(ctx: APIContext):
    from fastapi import Depends, FastAPI, HTTPException
    from fastapi.responses import StreamingResponse
    from .auth import make_auth
    from .models import ArpingResult, BackendStatus, SessionInfo, SessionUpdate, StatusInfo, UpdateResult
    from . import sessions as sess
    from .traffic import traffic_stream
    from .arp import arping_sync

    api_cfg = ctx.cfg.api
    auth    = make_auth(api_cfg)

    app = FastAPI(title='ISGd API', version='1.0',
                  docs_url='/docs', redoc_url=None)

    @app.get('/status', response_model=StatusInfo, dependencies=[Depends(auth)])
    async def get_status():
        counts = sess.fetch_counts()
        return StatusInfo(
            **counts,
            uptime_seconds=time.monotonic() - ctx.started_at,
            auth_backends=[BackendStatus(**b.status_dict()) for b in ctx.auth_pool],
            acct_backends=[BackendStatus(**b.status_dict()) for b in ctx.acct_pool],
        )

    @app.get('/sessions', response_model=list[SessionInfo], dependencies=[Depends(auth)])
    async def list_sessions(limit: int = 100, offset: int = 0):
        if limit < 1 or limit > 10000:
            raise HTTPException(status_code=422, detail='limit must be 1–10000')
        if offset < 0:
            raise HTTPException(status_code=422, detail='offset must be >= 0')
        return sess.fetch_all(limit=limit, offset=offset)

    @app.get('/sessions/{id}/arping', response_model=ArpingResult, dependencies=[Depends(auth)])
    async def arping_session(id: str):
        if _is_ip(id):
            ip = id
        else:
            s = sess.find_session(id)
            if s is None:
                raise HTTPException(status_code=404, detail='Session not found')
            ip = s['ip']
        try:
            return await asyncio.to_thread(arping_sync, ip)
        except OSError:
            return ArpingResult(ip=ip, iface=None, reachable=False,
                                packets_sent=0, packets_received=0,
                                rtt_ms=[], avg_rtt_ms=None)

    @app.get('/sessions/{id}', response_model=SessionInfo, dependencies=[Depends(auth)])
    async def get_session(id: str):
        s = sess.find_session(id)
        if s is None:
            raise HTTPException(status_code=404, detail='Session not found')
        return s

    @app.put('/sessions/{id}', response_model=UpdateResult, dependencies=[Depends(auth)])
    async def update_session(id: str, upd: SessionUpdate):
        if upd.approve is None and upd.block is None \
                and upd.in_kbps is None and upd.out_kbps is None:
            raise HTTPException(status_code=422, detail='At least one field required')

        s = sess.find_session(id)
        if s is None:
            raise HTTPException(status_code=404, detail='Session not found')

        return UpdateResult(**sess.apply_update(s, upd))

    _SSE_HEADERS = {
        'Cache-Control':    'no-cache',
        'X-Accel-Buffering': 'no',   # disable nginx response buffering
    }

    @app.get('/traffic/stream/{id}', dependencies=[Depends(auth)])
    async def stream_session_traffic(id: str, interval: float = 1.0):
        """SSE stream of in/out throughput for a single session (IP / session-id / MAC)."""
        if not 0.5 <= interval <= 30:
            raise HTTPException(status_code=422, detail='interval must be 0.5–30')
        return StreamingResponse(
            traffic_stream(id, interval),
            media_type='text/event-stream',
            headers=_SSE_HEADERS,
        )

    return app


# ── server runner ─────────────────────────────────────────────────────────────

class APIServer:
    def __init__(self, ctx: APIContext, stop: threading.Event):
        self._ctx  = ctx
        self._stop = stop

    def run(self) -> None:
        try:
            import uvicorn
        except ImportError:
            log.error('fastapi/uvicorn required for API: pip install fastapi uvicorn')
            return

        try:
            app = create_app(self._ctx)
        except ImportError:
            log.error('fastapi required for API: pip install fastapi uvicorn')
            return

        api_cfg = self._ctx.cfg.api
        config  = uvicorn.Config(
            app, host=api_cfg.host, port=api_cfg.port,
            log_level='warning', access_log=False,
        )
        server = uvicorn.Server(config)

        def _watch_stop():
            self._stop.wait()
            server.should_exit = True

        threading.Thread(target=_watch_stop, daemon=True).start()
        log.info('API server listening on %s:%d', api_cfg.host, api_cfg.port)
        server.run()
