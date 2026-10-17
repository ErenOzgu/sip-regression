"""Starts the PBX, runs the selected checks, writes the reports."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

from . import report as rep
from . import suite
from .pbx import Pbx, PbxError


def versions(pbx_binary: str) -> tuple[str, str]:
    def first(cmd: list[str]) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return ((p.stdout or "") + (p.stderr or "")).strip().splitlines()[0] if (p.stdout or p.stderr) else "?"
        except (OSError, subprocess.SubprocessError, IndexError):
            return "?"
    ast = first([pbx_binary, "-V"]).split("~")[0]
    sipp = next((line.strip() for line in subprocess.run(["sipp", "-v"], capture_output=True, text=True).stdout.splitlines()
                 if line.strip().startswith("SIPp")), "SIPp ?")
    return ast, sipp.split("-")[0]


def select(only: list[str] | None) -> list[suite.Case]:
    if not only:
        return list(suite.CASES)
    names = {c.name for c in suite.CASES}
    unknown = [o for o in only if o not in names]
    if unknown:
        raise SystemExit(f"unknown check(s): {', '.join(unknown)} (see --list)")
    chosen = [c for c in suite.CASES if c.name in only]
    return chosen


def run(only: list[str] | None, sip_port: int, binary: str, workdir: Path | None, keep: bool,
        artifacts: Path | None, quiet: bool = False) -> rep.Report:
    cases = select(only)
    own_dir = workdir is None
    work = Path(tempfile.mkdtemp(prefix="sip-regression-")) if own_dir else Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    ast, sipp_v = versions(binary)
    report = rep.Report(asterisk=ast, sipp=sipp_v)
    pbx = Pbx(work / "pbx", sip_port=sip_port, binary=binary)
    try:
        pbx.start()
    except PbxError as e:
        print(f"cannot start Asterisk: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    ctx = suite.Context(pbx, work)
    try:
        for c in cases:
            res = rep.CaseResult(c.name, c.title, c.group)
            started = time.time()
            mark = pbx.log_mark()
            try:
                c.fn(ctx)
            except suite.Failure as e:
                res.status, res.message = "failed", str(e)
            except Exception:
                res.status, res.message = "error", traceback.format_exc()
            res.seconds = time.time() - started
            if res.status != "passed":
                res.details = "\n".join(ctx.transcript[-6:]) + "\n--- Asterisk log during this check ---\n" + \
                    "\n".join(line for line in pbx.log_since(mark).splitlines() if "Remote UNIX" not in line)[-3000:]
            ctx.transcript.clear()
            report.results.append(res)
            if not quiet:
                print(rep.console_line(res), flush=True)
                if res.status != "passed":
                    print("      " + res.message.strip().replace("\n", "\n      "), flush=True)
    finally:
        pbx.stop()
        if artifacts:
            artifacts.mkdir(parents=True, exist_ok=True)
            for f in (work / "sipp").glob("*"):
                if f.suffix == ".log" and f.stat().st_size:
                    shutil.copy(f, artifacts / f.name)
            for name in ("full", "security"):
                src = work / "pbx" / "log" / name
                if src.exists():
                    shutil.copy(src, artifacts / f"asterisk-{name}.log")
        if own_dir and not keep:
            shutil.rmtree(work, ignore_errors=True)
    return report
