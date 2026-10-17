#!/usr/bin/env python3
"""Proves the checks can fail.

A test suite that has never failed proves little. This script breaks the test PBX on purpose,
one way at a time, and runs the check that is supposed to notice. Every mutant must make that
check fail; one that gets through means the suite has a blind spot.

    python3 hack/mutants.py            # all mutants
    python3 hack/mutants.py anonymous  # those whose name contains "anonymous"
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PBX = ROOT / "pbx"


def append(name: str, text: str):
    def edit(d: Path) -> None:
        with (d / name).open("a") as f:
            f.write("\n" + text + "\n")
    return edit


def replace(name: str, old: str, new: str):
    def edit(d: Path) -> None:
        t = (d / name).read_text()
        assert old in t, f"{old!r} not in {name}"
        (d / name).write_text(t.replace(old, new))
    return edit


# name, what is broken, edit, the checks that must catch it (any one failing is enough),
# and optionally the checks to run (default: the same ones; the health check needs traffic first)
MUTANTS = [
    ("anonymous-endpoint", "an [anonymous] endpoint lets unknown callers into the dialplan",
     append("pjsip.conf", "[anonymous]\ntype = endpoint\ncontext = internal\ndisallow = all\nallow = alaw"),
     ["invite_without_credentials"]),
    ("no-auth-on-endpoint", "endpoint 101 loses its auth line",
     replace("pjsip.conf", "auth = auth101\n", ""), ["invite_without_credentials", "options_needs_credentials",
                                                      "register_wrong_password"]),
    ("loose-rtp", "strict RTP is switched off", replace("rtp.conf", "strictrtp = ${STRICTRTP}", "strictrtp = no"),
     ["media_ignores_strangers"]),
    ("busy-answers", "extension 602 answers instead of reporting busy",
     replace("extensions.conf", "exten = 602,1,Busy(5)", "exten = 602,1,Answer()\n same = n,Wait(5)"), ["invite_busy"]),
    ("open-dialplan", "a catch-all pattern answers every number",
     replace("extensions.conf", "exten = i,1,Hangup()", "exten = _X.,1,Answer()\n same = n,Wait(2)\n same = n,Hangup()"),
     ["invite_unknown_extension"]),
    ("ami-on-all-interfaces", "the manager interface listens on every address",
     replace("manager.conf", "enabled = no", "enabled = yes\nbindaddr = 0.0.0.0"), ["listens_only_where_expected"]),
    ("http-on-all-interfaces", "the built-in web server listens on every address",
     replace("http.conf", "enabled = no", "enabled = yes\nbindaddr = 0.0.0.0"), ["listens_only_where_expected"]),
    ("sip-on-all-interfaces", "SIP listens on every address instead of the loopback one",
     replace("pjsip.conf", "bind = 127.0.0.1:${SIP_PORT}", "bind = 0.0.0.0:${SIP_PORT}"), ["listens_only_where_expected"]),
    ("broken-application", "an extension calls an application that does not exist",
     replace("extensions.conf", "exten = 601,1,Answer()\n same = n,Wait(1)", "exten = 601,1,Answer()\n same = n,NoSuchApplication()"),
     ["health_after_everything"], ["call_ended_by_pbx", "health_after_everything"]),
    ("short-call-never-ends", "extension 601 keeps the caller on the line",
     replace("extensions.conf", "exten = 601,1,Answer()\n same = n,Wait(1)", "exten = 601,1,Answer()\n same = n,Wait(60)"),
     ["call_ended_by_pbx"]),
]


def main() -> int:
    wanted = sys.argv[1:]
    failures = 0
    for name, what, edit, checks, *rest in MUTANTS:
        if wanted and not any(w in name for w in wanted):
            continue
        with tempfile.TemporaryDirectory(prefix="mutant-") as tmp:
            d = Path(tmp) / "pbx"
            shutil.copytree(PBX, d)
            edit(d)
            env = dict(os.environ, SIPREG_PBX_DIR=str(d))
            names = rest[0] if rest else checks
            p = subprocess.run([sys.executable, "-m", "sipreg", "--only", *names], cwd=ROOT, env=env,
                               capture_output=True, text=True)
            out = p.stdout + p.stderr
            caught = [c for c in checks if any(line.startswith(("FAIL", "ERR")) and f" {c} " in line for line in out.splitlines())]
            if p.returncode == 1 and caught:
                print(f"caught   {name:<24} {what}  [{', '.join(caught)}]")
            else:
                failures += 1
                print(f"MISSED   {name:<24} {what}\n{out[-1500:]}")
    print(f"\n{'all mutants were caught' if not failures else str(failures) + ' mutant(s) got through'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
