"""A very small SIP phone in plain Python, for the one thing SIPp is awkward at here:
checking that audio really comes back.

It places one authenticated call (INVITE, digest answer, ACK), exchanges RTP with the
PBX over loopback and hangs up. Nothing else: no registration, no retransmission, no
TCP. The scenarios under scenarios/ cover signalling; this covers media.
"""
from __future__ import annotations

import hashlib
import random
import re
import select
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field

CRLF = "\r\n"


class SipError(RuntimeError):
    pass


@dataclass
class Reply:
    status: int
    reason: str
    headers: dict[str, str]
    body: str


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def parse_reply(data: bytes) -> Reply:
    head, _, body = data.decode(errors="replace").partition(CRLF + CRLF)
    lines = head.split(CRLF)
    m = re.match(r"SIP/2\.0 (\d{3}) ?(.*)", lines[0])
    if not m:
        raise SipError(f"not a SIP response: {lines[0]!r}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), v.strip())
    return Reply(int(m.group(1)), m.group(2), headers, body)


def digest_response(user: str, password: str, realm: str, nonce: str, method: str, uri: str,
                    qop: str | None = "auth", nc: str = "00000001", cnonce: str = "") -> str:
    """RFC 2617 digest response, MD5."""
    ha1, ha2 = _md5(f"{user}:{realm}:{password}"), _md5(f"{method}:{uri}")
    if qop:
        return _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return _md5(f"{ha1}:{nonce}:{ha2}")


def digest_authorization(challenge: str, user: str, password: str, method: str, uri: str) -> str:
    fields = dict(re.findall(r'(\w+)="?([^",]+)"?', challenge))
    realm, nonce = fields["realm"], fields["nonce"]
    cnonce, nc = uuid.uuid4().hex[:16], "00000001"
    qop = "auth" if fields.get("qop", "").startswith("auth") else None
    response = digest_response(user, password, realm, nonce, method, uri, qop, nc, cnonce)
    extra = f', cnonce="{cnonce}", qop=auth, nc={nc}' if qop else ""
    opaque = f', opaque="{fields["opaque"]}"' if "opaque" in fields else ""
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
            f'response="{response}", algorithm=MD5{extra}{opaque}')


def rtp_packet(seq: int, ts: int, ssrc: int, payload: bytes, pt: int = 8) -> bytes:
    return struct.pack("!BBHII", 0x80, pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + payload


def rtp_parse(data: bytes) -> tuple[int, int, int, bytes] | None:
    """(sequence, timestamp, ssrc, payload) or None if this is not RTP."""
    if len(data) < 12 or data[0] >> 6 != 2:
        return None
    seq, ts, ssrc = struct.unpack("!HII", data[2:12])
    return seq, ts, ssrc, data[12:]


@dataclass
class Call:
    pbx_port: int
    user: str
    password: str
    extension: str
    sip_port: int
    rtp_port: int
    host: str = "127.0.0.1"
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16] + "@sip-regression")
    tag: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    remote_tag: str = ""
    media: tuple[str, int] | None = None
    cseq: int = 0
    sock: socket.socket | None = None
    rtp: socket.socket | None = None

    # -- plumbing -----------------------------------------------------------
    def _request(self, method: str, extra: str = "", body: str = "", branch: str | None = None) -> str:
        self.cseq += 1 if method != "ACK" else 0
        uri = f"sip:{self.extension}@{self.host}:{self.pbx_port}"
        to = f"<sip:{self.extension}@{self.host}>" + (f";tag={self.remote_tag}" if self.remote_tag else "")
        headers = [
            f"{method} {uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.host}:{self.sip_port};branch={branch or 'z9hG4bK' + uuid.uuid4().hex[:12]}",
            f"From: <sip:{self.user}@{self.host}>;tag={self.tag}",
            f"To: {to}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {self.cseq} {method}",
            f"Contact: <sip:{self.user}@{self.host}:{self.sip_port}>",
            "Max-Forwards: 70",
        ]
        if extra:
            headers.append(extra)
        if body:
            headers += ["Content-Type: application/sdp", f"Content-Length: {len(body)}"]
        else:
            headers.append("Content-Length: 0")
        return CRLF.join(headers) + CRLF + CRLF + body

    def _send(self, msg: str) -> None:
        assert self.sock is not None
        self.sock.sendto(msg.encode(), (self.host, self.pbx_port))

    def _await_final(self, timeout: float = 10.0) -> Reply:
        assert self.sock is not None
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([self.sock], [], [], 0.2)
            if not r:
                continue
            reply = parse_reply(self.sock.recvfrom(65535)[0])
            if reply.status >= 200:
                return reply
        raise SipError("no final answer from the PBX")

    def _sdp(self) -> str:
        return CRLF.join([
            "v=0", f"o={self.user} 1 1 IN IP4 {self.host}", "s=-", f"c=IN IP4 {self.host}", "t=0 0",
            f"m=audio {self.rtp_port} RTP/AVP 8", "a=rtpmap:8 PCMA/8000", "a=sendrecv", ""])

    # -- the call -----------------------------------------------------------
    def open(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.sip_port))
        self.rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp.bind((self.host, self.rtp_port))

    def close(self) -> None:
        for s in (self.sock, self.rtp):
            if s:
                s.close()
        self.sock = self.rtp = None

    def invite(self) -> Reply:
        """Places the call and returns the final answer (200 when it worked)."""
        first_branch = "z9hG4bK" + uuid.uuid4().hex[:12]
        self._send(self._request("INVITE", body=self._sdp(), branch=first_branch))
        reply = self._await_final()
        if reply.status == 401:
            self.remote_tag = ""  # the challenge's To tag belongs to a dead attempt
            self._ack_failure(reply, first_branch, cseq=self.cseq)
            uri = f"sip:{self.extension}@{self.host}:{self.pbx_port}"
            auth = "Authorization: " + digest_authorization(reply.headers["www-authenticate"], self.user,
                                                            self.password, "INVITE", uri)
            self._send(self._request("INVITE", extra=auth, body=self._sdp()))
            reply = self._await_final()
        if reply.status == 200:
            self._accept(reply)
        return reply

    def _ack_failure(self, reply: Reply, branch: str, cseq: int) -> None:
        to = reply.headers.get("to", "")
        msg = CRLF.join([
            f"ACK sip:{self.extension}@{self.host}:{self.pbx_port} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.host}:{self.sip_port};branch={branch}",
            f"From: <sip:{self.user}@{self.host}>;tag={self.tag}", f"To: {to}",
            f"Call-ID: {self.call_id}", f"CSeq: {cseq} ACK", "Max-Forwards: 70", "Content-Length: 0", "", ""])
        self._send(msg)

    def _accept(self, reply: Reply) -> None:
        m = re.search(r"tag=([^;>\s]+)", reply.headers.get("to", ""))
        self.remote_tag = m.group(1) if m else ""
        addr = re.search(r"^c=IN IP4 (\S+)", reply.body, re.M)
        port = re.search(r"^m=audio (\d+)", reply.body, re.M)
        if not (addr and port):
            raise SipError("the 200 OK carries no audio address:\n" + reply.body)
        self.media = (addr.group(1), int(port.group(1)))
        self._send(self._request("ACK"))

    def bye(self) -> Reply:
        self._send(self._request("BYE"))
        return self._await_final()


@dataclass
class EchoResult:
    sent: int
    received: int
    intact: int  # received packets whose payload equals one we sent
    in_order: bool
    first_delay_ms: float
    injected_back: int  # packets the PBX sent to a source that was never part of the call
    foreign_sent: int

    @property
    def loss_percent(self) -> float:
        return 100.0 * (self.sent - self.intact) / self.sent if self.sent else 100.0


def echo_test(call: Call, packets: int = 60, inject_from: int | None = None) -> EchoResult:
    """Send `packets` RTP packets (20 ms apart) into the call and collect what comes back.

    If inject_from is a port number, a second socket bound there plays an outsider: it fires
    RTP at the PBX's media port from the moment the call is up and reports whether anything
    is ever sent back to it.
    """
    assert call.rtp is not None and call.media is not None
    ssrc = random.getrandbits(32)
    outsider = None
    if inject_from:
        outsider = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outsider.bind((call.host, inject_from))
        outsider.setblocking(False)
    payloads: dict[int, bytes] = {}
    received: list[bytes] = []
    arrival: dict[int, float] = {}
    sent_at: dict[int, float] = {}
    foreign_sent = 0
    start = time.time()
    for i in range(packets):
        payload = bytes(((i * 7 + n) & 0xFF) for n in range(160))  # unique per packet
        payloads[i] = payload
        sent_at[i] = time.time()
        call.rtp.sendto(rtp_packet(i, 160 * i, ssrc, payload), call.media)
        if outsider is not None and i >= 5:  # after the PBX has locked on to the real phone
            for k in range(2):
                outsider.sendto(rtp_packet(50000 + i * 2 + k, 8000 * i, 0xBADBAD, b"\xd5" * 160), call.media)
                foreign_sent += 1
        deadline = start + (i + 1) * 0.02
        while time.time() < deadline:
            r, _, _ = select.select([call.rtp], [], [], max(0.0, deadline - time.time()))
            for s in r:
                data = s.recvfrom(2048)[0]
                received.append(data)
                arrival.setdefault(len(received) - 1, time.time())
    end = time.time() + 0.6  # let stragglers arrive
    while time.time() < end:
        r, _, _ = select.select([call.rtp], [], [], 0.1)
        for s in r:
            received.append(s.recvfrom(2048)[0])
            arrival.setdefault(len(received) - 1, time.time())
    parsed = [rtp_parse(d) for d in received]
    by_payload = {p: i for i, p in payloads.items()}
    got = [by_payload[pl] for pkt in parsed if pkt for pl in [pkt[3]] if pl in by_payload]
    injected_back = 0
    if outsider is not None:
        try:
            while True:
                outsider.recvfrom(2048)
                injected_back += 1
        except (BlockingIOError, OSError):
            pass
        outsider.close()
    first_delay = (arrival.get(0, time.time()) - sent_at[0]) * 1000 if received else float("nan")
    return EchoResult(sent=packets, received=len(received), intact=len(set(got)), in_order=got == sorted(got),
                      first_delay_ms=first_delay, injected_back=injected_back, foreign_sent=foreign_sent)
