"""Turns test results into JUnit XML (for CI dashboards) and a Markdown summary (for people)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

ICON = {"passed": "✅", "failed": "❌", "error": "💥", "skipped": "⏭️"}


@dataclass
class CaseResult:
    name: str
    title: str
    group: str
    status: str = "passed"  # passed | failed | error | skipped
    seconds: float = 0.0
    message: str = ""
    details: str = ""


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    asterisk: str = ""
    sipp: str = ""

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def ok(self) -> bool:
        return self.count("failed") == 0 and self.count("error") == 0

    @property
    def seconds(self) -> float:
        return sum(r.seconds for r in self.results)


def junit(report: Report) -> str:
    suite = ET.Element("testsuite", {
        "name": "sip-regression", "tests": str(len(report.results)),
        "failures": str(report.count("failed")), "errors": str(report.count("error")),
        "skipped": str(report.count("skipped")), "time": f"{report.seconds:.3f}",
    })
    props = ET.SubElement(suite, "properties")
    ET.SubElement(props, "property", {"name": "asterisk", "value": report.asterisk})
    ET.SubElement(props, "property", {"name": "sipp", "value": report.sipp})
    for r in report.results:
        tc = ET.SubElement(suite, "testcase", {"classname": f"sip-regression.{r.group}", "name": r.name,
                                               "time": f"{r.seconds:.3f}"})
        if r.status == "failed":
            ET.SubElement(tc, "failure", {"message": r.message.splitlines()[0] if r.message else "failed"}).text = r.message
        elif r.status == "error":
            ET.SubElement(tc, "error", {"message": r.message.splitlines()[0] if r.message else "error"}).text = r.message
        elif r.status == "skipped":
            ET.SubElement(tc, "skipped", {"message": r.message})
        if r.details:
            ET.SubElement(tc, "system-out").text = r.details
    ET.indent(suite)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suite, encoding="unicode") + "\n"


def markdown(report: Report) -> str:
    total = len(report.results)
    passed = report.count("passed")
    head = "## sip-regression: " + ("all passed" if report.ok else "FAILED")
    lines = [head, "", f"{passed} of {total} checks passed in {report.seconds:.0f} s"
             + (f" · {report.count('skipped')} skipped" if report.count("skipped") else "")
             + f" · {report.asterisk} · {report.sipp}", "",
             "| | Check | What it proves | Time |", "|---|---|---|---|"]
    for r in report.results:
        lines.append(f"| {ICON.get(r.status, '?')} | `{r.name}` | {r.title} | {r.seconds:.1f} s |")
    bad = [r for r in report.results if r.status in ("failed", "error")]
    for r in bad:
        lines += ["", f"<details open><summary><b>{r.name}</b>: {r.message.splitlines()[0] if r.message else r.status}"
                  "</summary>", "", "```text", (r.message + ("\n" + r.details if r.details else "")).strip()[-6000:],
                  "```", "", "</details>"]
    return "\n".join(lines) + "\n"


def console_line(r: CaseResult) -> str:
    mark = {"passed": "ok  ", "failed": "FAIL", "error": "ERR ", "skipped": "skip"}[r.status]
    return f"{mark}  {r.name:<34} {r.seconds:5.1f}s  {r.title}"
