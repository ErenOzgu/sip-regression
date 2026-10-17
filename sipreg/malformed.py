"""Hostile and broken SIP datagrams. Whatever the PBX does with them, it must stay up."""
from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass

CRLF = "\r\n"


def _msg(method="OPTIONS", uri="sip:127.0.0.1", via=None, extra=(), body="", cseq=None, call_id="x@y", max_forwards=70,
         from_="<sip:evil@127.0.0.1>;tag=1", to="<sip:127.0.0.1>", content_length=None):
    h = [f"{method} {uri} SIP/2.0"]
    for v in (["SIP/2.0/UDP 127.0.0.1:5999;branch=z9hG4bKevil1"] if via is None else via):
        h.append(f"Via: {v}")
    if from_ is not None:
        h.append(f"From: {from_}")
    if to is not None:
        h.append(f"To: {to}")
    if call_id is not None:
        h.append(f"Call-ID: {call_id}")
    h.append(f"CSeq: {cseq if cseq is not None else '1 ' + method}")
    h.append(f"Max-Forwards: {max_forwards}")
    h += list(extra)
    h.append(f"Content-Length: {len(body) if content_length is None else content_length}")
    return (CRLF.join(h) + CRLF + CRLF + body).encode("latin-1")


def cases(seed: int = 7) -> list[tuple[str, bytes]]:
    rnd = random.Random(seed)
    invite = _msg("INVITE", "sip:600@127.0.0.1", extra=["Contact: <sip:evil@127.0.0.1:5999>"])
    return [
        ("empty datagram", b""),
        ("single newline", b"\n"),
        ("keep-alive CRLFCRLF", b"\r\n\r\n"),
        ("random bytes", bytes(rnd.getrandbits(8) for _ in range(1200))),
        ("text that is not SIP", b"GET / HTTP/1.1\r\nHost: pbx\r\n\r\n"),
        ("wrong protocol version", _msg().replace(b"SIP/2.0", b"SIP/3.0", 1)),
        ("truncated in the middle of a header", invite[:90]),
        ("truncated after the request line", invite.split(b"\r\n")[0] + b"\r\n"),
        ("no Via", _msg(via=[])),
        ("no Call-ID", _msg(call_id=None)),
        ("no From", _msg(from_=None)),
        ("no To", _msg(to=None)),
        ("CSeq that overflows", _msg(cseq="99999999999999999999999 OPTIONS")),
        ("CSeq with another method", _msg(cseq="1 INVITE")),
        ("CSeq that is not a number", _msg(cseq="abc OPTIONS")),
        ("Max-Forwards 0", _msg(max_forwards=0)),
        ("Max-Forwards negative", _msg(max_forwards=-5)),
        ("Content-Length longer than the body", _msg(body="v=0", content_length=5000)),
        ("Content-Length negative", _msg(body="v=0", content_length=-1)),
        ("Content-Length not a number", _msg(body="v=0", content_length="lots")),
        ("body but no Content-Type", _msg("INVITE", "sip:600@127.0.0.1", body="v=0\r\n")),
        ("unknown method", _msg("FROBNICATE")),
        ("lowercase method", _msg().replace(b"OPTIONS", b"options", 1)),
        ("request URI of 8 KB", _msg(uri="sip:" + "a" * 8000 + "@127.0.0.1")),
        ("header value of 6 KB", _msg(extra=["X-Long: " + "B" * 6000])),
        ("a header name of 2 KB", _msg(extra=["X" * 2000 + ": 1"])),
        ("300 Via headers", _msg(via=[f"SIP/2.0/UDP 10.0.0.{i % 250}:5060;branch=z9hG4bK{i}" for i in range(300)])),
        ("1000 headers", _msg(extra=[f"X-{i}: {i}" for i in range(1000)])),
        ("NUL bytes in headers", _msg(extra=["X-Nul: a\x00b\x00c"], from_="<sip:ev\x00il@127.0.0.1>;tag=1")),
        ("bare LF instead of CRLF", _msg().replace(b"\r\n", b"\n")),
        ("header folded over many lines", _msg(extra=["Subject: a", " b", " c", "\td", " e"])),
        ("quote that never closes", _msg(from_='"Mallory <sip:evil@127.0.0.1>;tag=1')),
        ("angle bracket that never closes", _msg(from_="<sip:evil@127.0.0.1;tag=1")),
        ("percent escapes that are not hex", _msg(uri="sip:%zz%0@127.0.0.1")),
        ("SDP with port 0 and nonsense", _msg("INVITE", "sip:600@127.0.0.1", extra=["Content-Type: application/sdp"],
                                              body="v=0\r\nm=audio 0 RTP/AVP 999 -1\r\nc=IN IP4 999.999.999.999\r\n")),
        ("64 KB datagram", b"A" * 65000),
    ]


@dataclass
class Outcome:
    name: str
    answered: int | None  # status code of the first reply, None when the PBX stayed silent


def send_all(port: int, gap: float = 0.02, wait: float = 0.15) -> list[Outcome]:
    """Fire every case at the PBX from a fresh socket and note what, if anything, came back."""
    out: list[Outcome] = []
    for name, data in cases():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(wait)
        status = None
        try:
            s.sendto(data, ("127.0.0.1", port))
            reply, _ = s.recvfrom(65535)
            line = reply.split(b"\r\n", 1)[0].decode(errors="replace")
            status = int(line.split()[1]) if line.startswith("SIP/2.0 ") else -1
        except (TimeoutError, OSError, ValueError, IndexError):
            pass
        finally:
            s.close()
        out.append(Outcome(name, status))
        time.sleep(gap)
    return out


def flood(port: int, count: int = 1000) -> int:
    """Unauthenticated INVITEs as fast as the loopback takes them; returns how many were sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    sent = 0
    for i in range(count):
        data = _msg("INVITE", "sip:600@127.0.0.1", call_id=f"flood-{i}@x",
                    via=[f"SIP/2.0/UDP 127.0.0.1:{s.getsockname()[1]};branch=z9hG4bKflood{i}"],
                    extra=["Contact: <sip:evil@127.0.0.1>"])
        try:
            s.sendto(data, ("127.0.0.1", port))
            sent += 1
        except OSError:
            pass
    s.close()
    return sent
