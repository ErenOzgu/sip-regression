"""Reads SIPp's message trace and checks that the scenario itself spoke correct SIP.

A scenario that sends an ACK for a 4xx with a new branch still "passes" against many
servers (they just retransmit the answer until they give up). Checking the trace keeps
the scenarios honest, so a green run means the PBX was right, not that nobody noticed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SEPARATOR = re.compile(r"^-{20,} .*$", re.M)


@dataclass
class Message:
    direction: str  # "sent" or "received"
    start_line: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    @property
    def status(self) -> int | None:
        m = re.match(r"SIP/2\.0 (\d{3})", self.start_line)
        return int(m.group(1)) if m else None

    @property
    def method(self) -> str | None:
        return None if self.status is not None else self.start_line.split(" ", 1)[0]

    def header(self, name: str) -> str:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return ""

    @property
    def branch(self) -> str:
        m = re.search(r"branch=([^;>\s]+)", self.header("Via"))
        return m.group(1) if m else ""

    @property
    def call_id(self) -> str:
        return self.header("Call-ID")

    @property
    def cseq(self) -> tuple[int, str]:
        m = re.match(r"\s*(\d+)\s+(\S+)", self.header("CSeq"))
        return (int(m.group(1)), m.group(2)) if m else (0, "")


def parse(path: Path | None) -> list[Message]:
    if path is None or not Path(path).exists():
        return []
    text = Path(path).read_text(errors="replace").replace("\r\n", "\n")
    out: list[Message] = []
    for block in SEPARATOR.split(text):
        lines = block.strip("\n").split("\n")
        if not lines or not lines[0].startswith("UDP message"):
            continue
        direction = "sent" if "sent" in lines[0] else "received"
        rest = lines[1:]
        while rest and rest[0] == "":
            rest.pop(0)
        if not rest:
            continue
        msg = Message(direction, rest[0])
        i = 1
        while i < len(rest) and rest[i] != "":
            if ":" in rest[i]:
                k, v = rest[i].split(":", 1)
                msg.headers.append((k.strip(), v.strip()))
            i += 1
        msg.body = "\n".join(rest[i + 1:])
        out.append(msg)
    return out


def check_hygiene(msgs: list[Message]) -> list[str]:
    """Problems in what SIPp sent: an ACK for an error answer or a CANCEL on the wrong branch."""
    problems: list[str] = []
    invites: dict[tuple[str, int], Message] = {}
    final: dict[tuple[str, int], int] = {}
    for m in msgs:
        num, method = m.cseq
        key = (m.call_id, num)
        if m.direction == "sent" and m.method == "INVITE":
            invites[key] = m
        elif m.direction == "received" and m.status is not None and method == "INVITE" and m.status >= 200:
            final.setdefault(key, m.status)
        elif m.direction == "sent" and m.method == "ACK" and key in invites:
            status = final.get(key)
            if status is not None and status >= 300 and m.branch != invites[key].branch:
                problems.append(f"ACK for {status} to INVITE {num} uses branch {m.branch}, the INVITE used "
                                f"{invites[key].branch}")
        elif (m.direction == "sent" and m.method == "CANCEL" and key in invites
              and m.branch != invites[key].branch):
            problems.append(f"CANCEL uses branch {m.branch}, the INVITE it cancels used {invites[key].branch}")
    return problems
