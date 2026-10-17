"""Starts a throw-away Asterisk from the templates in pbx/ and lets tests look inside it."""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent.parent
# SIPREG_PBX_DIR points the suite at another PBX configuration: your own, or a deliberately broken
# one (hack/mutants.py does that to prove the checks can fail).
TEMPLATES = Path(os.environ.get("SIPREG_PBX_DIR") or ROOT / "pbx")
# Files that carry ${PLACEHOLDERS}; the rest are copied untouched (the dialplan
# has its own ${EXTEN}, which must survive).
RENDERED = {"pjsip.conf", "rtp.conf"}

PASSWORDS = {"PW_101": "s3cret-for-101", "PW_102": "s3cret-for-102"}


class PbxError(RuntimeError):
    pass


def find_module_dir() -> str:
    for base in ("/usr/lib", "/usr/lib64", "/usr/local/lib"):
        for p in Path(base).glob("**/asterisk/modules/app_dial.so"):
            return str(p.parent)
    raise PbxError("cannot find the Asterisk modules (is asterisk installed?)")


def render(workdir: Path, sip_port: int, rtp_start: int, rtp_end: int, moddir: str, strict_rtp: bool = True) -> Path:
    """Writes the configuration into workdir/etc and returns the path of asterisk.conf."""
    etc = workdir / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    values = dict(PASSWORDS, SIP_PORT=str(sip_port), RTP_START=str(rtp_start), RTP_END=str(rtp_end),
                  STRICTRTP="yes" if strict_rtp else "no")
    for src in sorted(TEMPLATES.iterdir()):
        text = src.read_text()
        if src.name in RENDERED:
            text = Template(text).substitute(values)
        (etc / src.name).write_text(text)
    for d in ("var", "spool", "run", "log", "agi"):
        (workdir / d).mkdir(exist_ok=True)
    (etc / "asterisk.conf").write_text(
        "[directories]\n"
        f"astetcdir => {etc}\n"
        f"astmoddir => {moddir}\n"
        "astvarlibdir => /var/lib/asterisk\n"
        f"astdbdir => {workdir}/var\n"
        f"astkeydir => {workdir}/var\n"
        "astdatadir => /usr/share/asterisk\n"
        f"astagidir => {workdir}/agi\n"
        f"astspooldir => {workdir}/spool\n"
        f"astrundir => {workdir}/run\n"
        f"astlogdir => {workdir}/log\n"
        "[options]\n"
        "verbose = 3\n"
    )
    return etc / "asterisk.conf"


class Pbx:
    def __init__(self, workdir: Path, sip_port: int = 5160, rtp_start: int = 20000, rtp_end: int = 20199,
                 binary: str = "asterisk", strict_rtp: bool = True):
        self.workdir = Path(workdir)
        self.sip_port = sip_port
        self.rtp_range = (rtp_start, rtp_end)
        self.binary = binary
        self.strict_rtp = strict_rtp
        self.conf: Path | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self, timeout: float = 60.0) -> None:
        if shutil.which(self.binary) is None:
            raise PbxError(f"{self.binary} is not installed")
        self.conf = render(self.workdir, self.sip_port, *self.rtp_range, find_module_dir(), self.strict_rtp)
        out = subprocess.run([self.binary, "-C", str(self.conf)], capture_output=True, text=True, timeout=timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "fully booted" in self.cli("core waitfullybooted", check=False):
                return
            time.sleep(0.5)
        raise PbxError("Asterisk did not finish booting:\n" + out.stdout + out.stderr + self.log_text()[-2000:])

    def stop(self) -> None:
        if self.conf is None:
            return
        self.cli("core stop now", check=False)
        for _ in range(40):
            if not self.alive():
                break
            time.sleep(0.25)
        self.conf = None

    # -- looking inside ----------------------------------------------------
    def cli(self, command: str, check: bool = True) -> str:
        if self.conf is None:
            raise PbxError("Asterisk is not running")
        p = subprocess.run([self.binary, "-C", str(self.conf), "-rx", command], capture_output=True, text=True,
                           timeout=30)
        if check and p.returncode != 0:
            raise PbxError(f"asterisk -rx {command!r} failed: {p.stdout}{p.stderr}")
        return p.stdout + p.stderr

    def pid(self) -> int | None:
        f = self.workdir / "run" / "asterisk.pid"
        try:
            return int(f.read_text().strip())
        except (OSError, ValueError):
            return None

    def alive(self) -> bool:
        pid = self.pid()
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return Path(f"/proc/{pid}").exists()

    def rss_kb(self) -> int:
        pid = self.pid()
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
        raise PbxError("no VmRSS")

    def active_channels(self) -> int:
        m = re.search(r"(\d+) active channels?", self.cli("core show channels count"))
        if not m:
            raise PbxError("cannot read the channel count")
        return int(m.group(1))

    def contacts(self) -> list[str]:
        """Names of the registered PJSIP contacts (endpoint ids)."""
        out = self.cli("pjsip show contacts")
        return sorted(set(re.findall(r"Contact:\s+(\w+)/", out)))

    def listeners(self) -> list[str]:
        """Sockets Asterisk is listening on, like "udp 127.0.0.1:5160".

        TCP counts only in state LISTEN. UDP sockets on the kernel's ephemeral ports are left out:
        they are the PBX's own client sockets (Asterisk opens one for DNS lookups), not services.
        """
        try:
            low = int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            low = 32768
        pid = self.pid()
        inodes: set[str] = set()
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", target)
            if m:
                inodes.add(m.group(1))
        found: set[str] = set()
        for proto in ("tcp", "udp", "tcp6", "udp6"):
            try:
                rows = Path(f"/proc/net/{proto}").read_text().splitlines()[1:]
            except OSError:
                continue
            for row in rows:
                f = row.split()
                if f[9] not in inodes or (proto.startswith("tcp") and f[3] != "0A"):
                    continue
                addr, port = f[1].split(":")
                if proto.startswith("udp") and int(port, 16) >= low:
                    continue
                found.add(f"{proto[:3]} {_hex_addr(addr)}:{int(port, 16)}")
        return sorted(found)

    def log_text(self) -> str:
        try:
            return (self.workdir / "log" / "full").read_text(errors="replace")
        except OSError:
            return ""

    def security_log(self) -> str:
        try:
            return (self.workdir / "log" / "security").read_text(errors="replace")
        except OSError:
            return ""

    def log_mark(self) -> int:
        """A position in the log; log_since(mark) returns what was written after it."""
        return len(self.log_text())

    def log_since(self, mark: int) -> str:
        return self.log_text()[mark:]

    def kill(self) -> None:
        pid = self.pid()
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def _hex_addr(h: str) -> str:
    """/proc/net prints addresses as little-endian hex words."""
    if len(h) == 8:
        return ".".join(str(b) for b in bytes.fromhex(h)[::-1])
    words = [bytes.fromhex(h[i:i + 8])[::-1].hex() for i in range(0, 32, 8)]
    packed = bytes.fromhex("".join(words))
    if packed == bytes(15) + b"\x01":
        return "::1"
    if packed == bytes(16):
        return "::"
    return ":".join(packed[i:i + 2].hex() for i in range(0, 16, 2))
