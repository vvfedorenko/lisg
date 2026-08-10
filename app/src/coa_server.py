"""CoA server — receives and processes CoA/Disconnect-Request packets (RFC 5176)."""
from __future__ import annotations

import logging
import re
import socket
import struct
import threading
from typing import Optional

try:
    import pyrad.packet as rp_pkt
    from pyrad.dictionary import Dictionary as RadDict
except ImportError:
    raise ImportError('pyrad required: pip install pyrad')

from . import isg
from . import services as svc_mod
from .config import Config
from .radius_packet import NAMES, CODES, ERROR_CAUSES, attr_get


def _verify_coa_auth(data: bytes, secret: bytes) -> bool:
    """Verify the request authenticator in a CoA/Disconnect-Request."""
    if len(data) < 20:
        return False
    zeroed = data[:4] + b'\x00' * 16 + data[20:]
    import hashlib
    return data[4:20] == hashlib.md5(zeroed + secret).digest()


def _send_coa_reply(sock: socket.socket, peer: tuple,
                    req_id: int, req_auth: bytes,
                    out_code: str, out_err: Optional[str], secret: bytes) -> None:
    """Build and send CoA-ACK / CoA-NAK / Disconnect-ACK / Disconnect-NAK."""
    import hashlib
    code_int = CODES.get(out_code, 0)
    attrs    = b''
    if out_err:
        cause = ERROR_CAUSES.get(out_err, 0)
        if cause:
            attrs = bytes([101, 6]) + struct.pack('>I', cause)
    length = 20 + len(attrs)
    header = bytes([code_int, req_id]) + struct.pack('>H', length)
    auth   = hashlib.md5(header + req_auth + attrs + secret).digest()
    try:
        sock.sendto(header + auth + attrs, peer)
    except OSError as e:
        log.error('CoA reply send failed: %s', e)

log = logging.getLogger(__name__)


class CoAServer:
    """
    Listens on the CoA UDP port and processes Disconnect-Request / CoA-Request
    packets.  Call run() from a daemon thread; signal stop via the threading.Event
    passed to the constructor.
    """

    def __init__(self, cfg: Config, nas_ip: str, nas_id: str,
                 rad_dict: RadDict, stop: threading.Event):
        self._cfg      = cfg
        self._nas_ip   = nas_ip
        self._nas_id   = nas_id
        self._rad_dict = rad_dict
        self._stop     = stop

    # ── public entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', self._cfg.coa_port))
            sock.settimeout(1.0)
        except OSError as e:
            log.error('Cannot create CoA socket: %s', e)
            return

        nl = isg.open_socket()
        try:
            while not self._stop.is_set():
                try:
                    data, peer = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError as e:
                    log.error('CoA recv error: %s', e)
                    continue
                self._handle_packet(data, peer, nl, sock)
        finally:
            sock.close()
            nl.close()

    # ── packet dispatch ───────────────────────────────────────────────────────

    def _handle_packet(self, data: bytes, peer: tuple,
                       nl: socket.socket, udp: socket.socket) -> None:
        secret   = self._cfg.coa_secret
        peer_ip  = peer[0]

        if self._cfg.coa_server and peer_ip != self._cfg.coa_server:
            log.error('CoA from %s denied (only %s allowed)',
                      peer_ip, self._cfg.coa_server)
            return
        if not _verify_coa_auth(data, secret):
            log.error('CoA from %s: bad authenticator', peer_ip)
            return

        try:
            pkt = rp_pkt.Packet(secret=secret, dict=self._rad_dict, packet=data)
        except Exception:
            log.error('Cannot parse CoA from %s', peer_ip)
            return

        code = NAMES.get(pkt.code, '')
        if code == 'Disconnect-Request':
            ack, nak = 'Disconnect-ACK', 'Disconnect-NAK'
        elif code == 'CoA-Request':
            ack, nak = 'CoA-ACK', 'CoA-NAK'
        else:
            log.error('Unexpected CoA code from %s: %s', peer_ip, code)
            return

        out_code, out_err, ev = nak, None, {}

        nas_ident  = attr_get(pkt, 'NAS-Identifier')
        nas_ipaddr = attr_get(pkt, 'NAS-IP-Address')
        if ((nas_ident is None and nas_ipaddr is None)
                or (nas_ident  is not None and self._nas_id != str(nas_ident))
                or (nas_ipaddr is not None and self._nas_ip != str(nas_ipaddr))):
            out_err = 'NAS-Identification-Mismatch'
            log.error('CoA: NAS identification mismatch')
        else:
            session_id = attr_get(pkt, 'Acct-Session-Id')
            nas_port   = attr_get(pkt, 'NAS-Port')
            username   = attr_get(pkt, 'User-Name')
            if username and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(username)):
                username = None

            if session_id:
                ev['session_id'] = isg.session_id_to_bytes(str(session_id))
            elif nas_port is not None:
                ev['port_number'] = int(nas_port)
            elif username:
                ev['ipaddr'] = isg.ip2long(str(username))
            else:
                out_err = 'Missing-Attribute'
                log.error('CoA: need session-id, NAS-Port, or User-Name')

            if out_err is None:
                if code == 'Disconnect-Request':
                    ev['type'] = isg.EVENT_SESS_CLEAR
                else:
                    ev, out_err = self._parse_coa_change(pkt, ev, nl)

            if out_err is None:
                try:
                    rep = isg.send_event(nl, ev)
                    if rep['type'] == isg.EVENT_KERNEL_ACK:
                        out_code = ack
                    else:
                        out_err  = 'Session-Context-Not-Found'
                except OSError as e:
                    log.error('CoA netlink error: %s', e)
                    out_err = 'Session-Context-Not-Found'

        _send_coa_reply(udp, peer, pkt.id, pkt.authenticator,
                        out_code, out_err, secret)

    # ── CoA-Request change parsing ────────────────────────────────────────────

    def _parse_coa_change(self, pkt, ev: dict,
                          nl: socket.socket) -> tuple[dict, Optional[str]]:
        rate_info: list = []
        for ai in (pkt.get('Cisco-Account-Info') or []):
            if str(ai).upper().startswith('Q'):
                rate_info = svc_mod.parse_qos(str(ai))

        av: dict = {}
        for ap in (pkt.get('Cisco-AVPair') or []):
            m = re.match(r'^subscriber:([^=]+)=(.+)', str(ap))
            if m:
                av[m.group(1)] = m.group(2)

        cmd = av.get('command', '')
        if re.match(r'(a|dea)ctivate-service', cmd):
            svc_name = av.get('service-name')
            if not svc_name:
                return ev, 'Missing-Attribute'

            srv_list: dict = {}
            svc_sid        = None
            try:
                for cev in isg.get_list(nl, {'type': isg.EVENT_SERV_GETLIST})[0]:
                    sn = cev.get('service_name')
                    if sn:
                        srv_list[sn] = 'A' if (cev['flags'] & isg.SERVICE_STATUS_ON) else 'N'
                        if sn == svc_name:
                            svc_sid = isg.session_id_to_bytes(cev['session_id'])
            except OSError:
                pass

            if svc_sid is None:
                log.error("CoA: service '%s' not found", svc_name)
                return ev, 'Session-Context-Not-Found'

            flags_op = isg.FLAG_OP_SET if cmd == 'activate-service' else isg.FLAG_OP_UNSET
            srv_list[svc_name] = 'A' if flags_op == isg.FLAG_OP_SET else 'N'
            srv_list = svc_mod.sanitize(self._cfg, srv_list)

            if flags_op == isg.FLAG_OP_SET and srv_list.get(svc_name) == 'N':
                return ev, None

            ev = svc_mod.build_event(self._cfg, svc_name)
            ev.update(session_id=svc_sid,
                      flags=isg.IS_SERVICE | isg.SERVICE_STATUS_ON,
                      flags_op=flags_op)
        elif cmd:
            log.error("CoA: unknown command '%s'", cmd)
            return ev, 'Unsupported-Attribute'

        if len(rate_info) == 4:
            ev.update(in_rate=rate_info[0], in_burst=rate_info[1],
                      out_rate=rate_info[2], out_burst=rate_info[3])
        ev.setdefault('type', isg.EVENT_SESS_CHANGE)
        return ev, None
