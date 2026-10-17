"""Writes the RTP audio SIPp plays into a call: 20 ms of A-law, as an Ethernet/IPv4/UDP/RTP pcap.

SIPp rewrites the addresses and ports when it plays the file, so any values do. Generating
the file here means the repository carries no binary and does not depend on where a
distribution puts its sample pcap.
"""
from __future__ import annotations

import struct
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
ALAW_SILENCE = 0xD5  # what a quiet line sounds like in G.711 A-law


def rtp_packet(seq: int, timestamp: int, ssrc: int, payload: bytes, pt: int = 8) -> bytes:
    return struct.pack("!BBHII", 0x80, pt, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc) + payload


def frame(udp_payload: bytes, sport: int = 6000, dport: int = 6002) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(udp_payload), 0) + udp_payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + udp
    return bytes(6) + bytes(6) + b"\x08\x00" + ip


def write_g711a(path: Path, packets: int = 150) -> Path:
    """packets * 20 ms of audio; the default is three seconds."""
    out = bytearray(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
    for i in range(packets):
        # A faint ramp instead of flat silence, so an echo that comes back as zeros is noticed.
        payload = bytes((ALAW_SILENCE ^ ((i + n) & 0x0F)) for n in range(160))
        data = frame(rtp_packet(i, 160 * i, 0x5EED5EED, payload))
        t = i * 20000
        out += struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(data), len(data)) + data
    path.write_bytes(bytes(out))
    return path
