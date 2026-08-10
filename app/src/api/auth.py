"""FastAPI auth dependency — Bearer token + optional IP access list."""
from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import APIConfig

_bearer = HTTPBearer(auto_error=False)


def make_auth(cfg: APIConfig):
    """Return a FastAPI dependency that enforces token and/or access-list."""

    async def _check(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    ) -> None:
        # ── IP access list ────────────────────────────────────────────────────
        if cfg.access_list:
            host = request.client.host if request.client else None
            try:
                client_ip = ipaddress.ip_address(host) if host else None
            except ValueError:
                client_ip = None
            allowed = client_ip is not None and any(
                client_ip in ipaddress.ip_network(cidr, strict=False)
                for cidr in cfg.access_list
            )
            if not allowed:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail='Client IP not in access list')

        # ── Bearer token ──────────────────────────────────────────────────────
        # Query-param fallback allows browser EventSource (which can't set headers)
        if cfg.token:
            bearer = credentials.credentials if credentials else None
            query_token = request.query_params.get('token')
            if bearer != cfg.token and query_token != cfg.token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Invalid or missing token',
                    headers={'WWW-Authenticate': 'Bearer'},
                )

    return _check
