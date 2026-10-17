"""python3 -m sipreg [--list] [--only NAME ...] [--junit FILE] [--summary FILE]"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import report as rep
from . import runner, suite


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sipreg", description="SIPp scenarios against a throw-away Asterisk.")
    ap.add_argument("--list", action="store_true", help="list the checks and exit")
    ap.add_argument("--only", nargs="+", metavar="NAME", help="run just these checks")
    ap.add_argument("--junit", metavar="FILE", help="write a JUnit XML report")
    ap.add_argument("--summary", metavar="FILE", help="write a Markdown summary (default: $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--artifacts", metavar="DIR", help="copy SIPp traces and Asterisk logs here")
    ap.add_argument("--port", type=int, default=5160, help="SIP port the test PBX listens on (default 5160)")
    ap.add_argument("--asterisk", default="asterisk", help="asterisk binary (default: asterisk)")
    ap.add_argument("--workdir", help="keep everything in this directory instead of a temporary one")
    ap.add_argument("--keep", action="store_true", help="do not delete the temporary directory")
    args = ap.parse_args(argv)

    if args.list:
        for c in suite.CASES:
            print(f"{c.name:<38} {c.group:<11} {c.title}")
        return 0

    report = runner.run(args.only, args.port, args.asterisk, Path(args.workdir) if args.workdir else None,
                        args.keep, Path(args.artifacts) if args.artifacts else None)
    if args.junit:
        Path(args.junit).write_text(rep.junit(report))
    summary = args.summary or os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(rep.markdown(report))
    print(f"\n{report.count('passed')} passed, {report.count('failed')} failed, {report.count('error')} errors, "
          f"{report.count('skipped')} skipped in {report.seconds:.0f} s ({report.asterisk}, {report.sipp})")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
