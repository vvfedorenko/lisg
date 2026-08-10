"""Blocking RADIUS backend — wraps a single ServerEntry."""
from __future__ import annotations

import hashlib
import hmac
import logging
import socket
import struct
import threading

try:
    import pyrad.packet as rp
    from pyrad.dictionary import Dictionary as RadDict
except ImportError:
    raise ImportError('pyrad required: pip install pyrad')

from .. import isg
from .. import radius_packet as rad
from ..config import Config, ServerEntry
from .base import AuthResult, Backend, BackendUnavailable, apply_account_info

log = logging.getLogger(__name__)

_id_lock    = threading.Lock()
_id_counter = [0]


def _next_id() -> int:
    with _id_lock:
        rid = _id_counter[0] % 256
        _id_counter[0] += 1
    return rid


def _build_raw_auth(pkt) -> bytes:
    """Assemble an Access-Request with a correct Message-Authenticator."""
    attr = pkt._PktEncodeAttributes()
    raw  = struct.pack('!BBH', pkt.code, pkt.id, 20 + len(attr)) + pkt.authenticator + attr
    ma_old = bytes([80, 18]) + b'\x00' * 16
    ma_new = bytes([80, 18]) + hmac.new(pkt.secret, raw, hashlib.md5).digest()
    return raw.replace(ma_old, ma_new, 1)


class RadiusBackend(Backend):
    """
    Single RADIUS server backend.  authenticate() / account() each open one
    UDP socket, send, and wait.  Raises BackendUnavailable on timeout or
    network error so the caller can fall through to the next pool entry.
    """

    def __init__(self, entry: ServerEntry, cfg: Config,
                 nas_ip: str, nas_id: str, rad_dict: RadDict):
        super().__init__()
        self._entry    = entry
        self._cfg      = cfg
        self._nas_ip   = nas_ip
        self._nas_id   = nas_id
        self._rad_dict = rad_dict
        self.label     = f'radius {entry.server}'

    # ── public interface ──────────────────────────────────────────────────────

    def authenticate(self, ev: dict) -> AuthResult:
        host, port = self._entry.host_port()
        rid  = _next_id()
        try:
            pkt  = rad.build('Access-Request', ev, self._entry.secret, rid,
                             self._rad_dict, self._nas_ip, self._nas_id)
            data = _build_raw_auth(pkt)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self._entry.timeout)
                sock.connect((host, port))
                sock.send(data)
                reply_bytes = sock.recv(4096)
            reply = rp.Packet(secret=self._entry.secret,
                              dict=self._rad_dict,
                              packet=reply_bytes)
            if reply.id != rid:
                self.record_err()
                raise BackendUnavailable(f'{host}:{port} returned wrong id')
            self.record_ok()
            return self._parse_auth_reply(reply)
        except socket.timeout:
            self.record_err()
            raise BackendUnavailable(f'RADIUS timeout from {host}:{port}')
        except BackendUnavailable:
            raise
        except OSError as e:
            self.record_err()
            raise BackendUnavailable(f'RADIUS error to {host}:{port}: {e}')

    def account(self, ev: dict) -> None:
        host, port = self._entry.host_port()
        rid  = _next_id()
        try:
            pkt  = rad.build('Accounting-Request', ev, self._entry.secret, rid,
                             self._rad_dict, self._nas_ip, self._nas_id)
            data = pkt.RequestPacket()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self._entry.timeout)
                sock.connect((host, port))
                sock.send(data)
                sock.recv(4096)     # Accounting-Response; content ignored
            self.record_ok()
        except socket.timeout:
            self.record_err()
            log.error('RADIUS acct timeout from %s:%d', host, port)
        except OSError as e:
            self.record_err()
            log.error('RADIUS acct error to %s:%d: %s', host, port, e)

    # ── reply parsing ─────────────────────────────────────────────────────────

    def _parse_auth_reply(self, pkt) -> AuthResult:
        code   = rad.NAMES.get(pkt.code, '')
        result = AuthResult()

        if code == 'Access-Accept':
            result.accept = True
            apply_account_info(result, pkt.get('Cisco-Account-Info') or [])

            nat_ip = rad.attr_get(pkt, 'Framed-IP-Address')
            if nat_ip is not None:
                result.nat_ip = str(nat_ip)
            for attr, field in (('Acct-Interim-Interval', 'alive_interval'),
                                 ('Session-Timeout',       'max_duration'),
                                 ('Idle-Timeout',          'idle_timeout')):
                v = rad.attr_get(pkt, attr)
                if v is not None:
                    setattr(result, field, int(v))
            cls_attr = rad.attr_get(pkt, 'Class')
            if cls_attr:
                result.cookie = str(cls_attr)[:32]

        elif code == 'Access-Reject':
            # result.accept stays False; the walled-garden services from
            # cfg.unauth_service_name_list are applied centrally in isg_server.
            pass
        else:
            log.error("Unexpected RADIUS reply code '%s'", code)

        return result
