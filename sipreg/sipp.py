"""Runs one SIPp scenario and reads back what happened."""
from __future__ import annotations

import csv
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"

EXIT_MEANING = {
    0: "all calls succeeded",
    1: "at least one call failed",
    97: "exit on an internal command",
    99: "no call was processed",
    -1: "fatal error",
    -2: "fatal error (cannot bind the local port)",
}


@dataclass
class SippResult:
    scenario: str
    returncode: int
    seconds: float
    calls: int = 0
    failed: int = 0
    retransmissions: int = 0
    output: str = ""
    errors: str = ""
    messages: Path | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.failed == 0 and self.calls > 0

    def explain(self) -> str:
        why = EXIT_MEANING.get(self.returncode, f"exit code {self.returncode}")
        text = f"{self.scenario}: {why}; {self.calls} call(s), {self.failed} failed, {self.retransmissions} retransmission(s)"
        if self.errors.strip():
            text += "\n" + "\n".join("    " + line for line in self.errors.strip().splitlines()[-25:])
        elif self.output.strip():
            text += "\n" + "\n".join("    " + line for line in self.output.strip().splitlines()[-12:])
        return text


def _read_stats(path: Path) -> dict[str, str]:
    try:
        with path.open(newline="") as f:
            rows = list(csv.DictReader(f, delimiter=";"))
    except OSError:
        return {}
    return rows[-1] if rows else {}


def _int(row: dict[str, str], key: str) -> int:
    try:
        return int(float(row.get(key, "0") or 0))
    except ValueError:
        return 0


class Running:
    """A SIPp process that has been started and not yet waited for."""

    def __init__(self, scenario: str, proc: subprocess.Popen, started: float, files: dict[str, Path], timeout: int):
        self.scenario, self.proc, self.started, self.files, self.timeout = scenario, proc, started, files, timeout

    def finish(self) -> SippResult:
        try:
            out, _ = self.proc.communicate(timeout=self.timeout + 30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
            out = (out or "") + "\nkilled by the runner: SIPp did not stop by itself"
        row = _read_stats(self.files["stats"])
        errors, messages = self.files["errors"], self.files["messages"]
        return SippResult(
            scenario=self.scenario, returncode=self.proc.returncode, seconds=time.time() - self.started,
            calls=_int(row, "TotalCallCreated"), failed=_int(row, "FailedCall(C)"),
            retransmissions=_int(row, "Retransmissions(C)"), output=out or "",
            errors=errors.read_text(errors="replace") if errors.exists() else "",
            messages=messages if messages.exists() else None,
        )

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()


def start(scenario: str, *, target_port: int, local_port: int, workdir: Path, user: str = "101",
          password: str = "", service: str = "600", calls: int = 1, rate: float | None = None,
          max_concurrent: int | None = None, timeout: int = 30, extra: list[str] | None = None,
          label: str | None = None, contact_port: int | None = None, binary: str = "sipp") -> Running:
    """Start scenarios/<scenario>.xml against 127.0.0.1:target_port.

    -au/-ap are what the [authentication] keyword uses; -s is the user part of the
    request URI; "user" and "contact_port" (where a REGISTER says the phone can be reached;
    default: the local port) are available in the XML as [user] and [contact_port]. label keeps the log files of
    two runs of the same scenario apart.
    """
    if shutil.which(binary) is None:
        raise RuntimeError(f"{binary} is not installed")
    workdir.mkdir(parents=True, exist_ok=True)
    tag = label or scenario
    files = {
        "stats": workdir / f"{tag}.stat.csv",
        "errors": workdir / f"{tag}.errors.log",
        "messages": workdir / f"{tag}.messages.log",
    }
    for f in files.values():
        f.unlink(missing_ok=True)
    cmd = [
        binary, f"127.0.0.1:{target_port}", "-sf", str(SCENARIOS / f"{scenario}.xml"),
        "-i", "127.0.0.1", "-p", str(local_port), "-t", "u1", "-nostdin",
        "-m", str(calls), "-timeout", f"{timeout}s", "-timeout_error",
        "-au", user, "-ap", password, "-s", service, "-key", "user", user, "-key", "contact_port", str(contact_port or local_port),
        "-trace_err", "-error_file", str(files["errors"]), "-trace_msg", "-message_file", str(files["messages"]),
        "-trace_stat", "-stf", str(files["stats"]), "-stat_delimiter", ";", "-fd", "1",
        "-max_retrans", "3",
    ]
    if rate:
        cmd += ["-r", str(rate)]
    if max_concurrent:
        cmd += ["-l", str(max_concurrent)]
    cmd += extra or []
    proc = subprocess.Popen(cmd, cwd=workdir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    return Running(label or scenario, proc, time.time(), files, timeout)


def run(scenario: str, **kwargs) -> SippResult:
    """start() and wait for the result."""
    return start(scenario, **kwargs).finish()


def responses(result: SippResult) -> list[str]:
    """Status lines the PBX sent, in order, read from the message trace."""
    if result.messages is None:
        return []
    return re.findall(r"^SIP/2\.0 (\d{3} [^\r\n]*)", result.messages.read_text(errors="replace"), re.M)
