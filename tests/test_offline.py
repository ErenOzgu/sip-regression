"""Tests that need neither Asterisk nor SIPp: the parts of the harness that are plain code."""
from __future__ import annotations

import importlib.util
import re
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from sipreg import malformed, pbx, pcap, report, sipp, suite, trace, ua

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"


class Scenarios(unittest.TestCase):
    def test_all_are_well_formed_xml(self):
        files = sorted(SCENARIOS.glob("*.xml"))
        self.assertGreater(len(files), 10)
        for f in files:
            ET.parse(f)

    def test_every_scenario_is_used_and_every_use_exists(self):
        src = (ROOT / "sipreg" / "suite.py").read_text()
        used = set(re.findall(r'ctx\.sipp\(\s*"(\w+)"', src)) | set(re.findall(r'ctx\.phone\(\s*"\d+",\s*"(\w+)"', src))
        have = {f.stem for f in SCENARIOS.glob("*.xml")}
        self.assertEqual(used - have, set(), "a check names a scenario that does not exist")
        self.assertEqual(have - used, set(), "a scenario is never run")

    def test_branch_offsets_point_at_the_right_message(self):
        """[branch-N] counts messages back from the current one. Get N wrong and an ACK or CANCEL
        silently uses a new transaction, so this recomputes every offset from the XML."""
        for f in sorted(SCENARIOS.glob("*.xml")):
            steps = [e for e in ET.parse(f).getroot() if e.tag in ("send", "recv", "pause", "nop")]
            invite_index: dict[str, int] = {}
            for i, step in enumerate(steps):
                text = step.findtext("") or "".join(step.itertext())
                first = text.strip().splitlines()[0].strip() if text.strip() else ""
                cseq = re.search(r"CSeq:\s*(\d+)\s+(\w+)", text)
                if step.tag == "send" and first.startswith("INVITE") and cseq:
                    invite_index[cseq.group(1)] = i
                m = re.search(r"branch=\[branch-(\d+)\]", text)
                if m and cseq:
                    target = invite_index.get(cseq.group(1))
                    self.assertIsNotNone(target, f"{f.name}: step {i} reuses a branch but no INVITE {cseq.group(1)} came before")
                    self.assertEqual(i - int(m.group(1)), target,
                                     f"{f.name}: step {i} ({first.split()[0]}) uses [branch-{m.group(1)}], "
                                     f"the INVITE it belongs to is step {target}")
                if first.startswith("CANCEL"):
                    self.assertIsNotNone(m, f"{f.name}: a CANCEL must reuse the INVITE's branch")


class Trace(unittest.TestCase):
    def block(self, direction, lines):
        head = "UDP message sent (1 bytes):" if direction == "sent" else "UDP message received [1] bytes :"
        return ("----------------------------------------------- 2026-01-01 00:00:00.000000\n" + head + "\n\n"
                + "\r\n".join(lines) + "\r\n\r\n\n")

    def msg(self, start, branch, cseq, call_id="c1"):
        return [start, f"Via: SIP/2.0/UDP 127.0.0.1:5180;branch={branch}", f"Call-ID: {call_id}", f"CSeq: {cseq}"]

    def write(self, *blocks):
        d = tempfile.mkdtemp()
        p = Path(d) / "trace.log"
        p.write_text("".join(blocks))
        return p

    def test_parse(self):
        p = self.write(self.block("sent", self.msg("INVITE sip:a@b SIP/2.0", "z9hG4bK1", "1 INVITE")),
                       self.block("received", self.msg("SIP/2.0 486 Busy Here", "z9hG4bK1", "1 INVITE")))
        m = trace.parse(p)
        self.assertEqual([x.direction for x in m], ["sent", "received"])
        self.assertEqual((m[0].method, m[0].branch, m[0].cseq), ("INVITE", "z9hG4bK1", (1, "INVITE")))
        self.assertEqual(m[1].status, 486)

    def test_ack_for_error_must_reuse_the_invite_branch(self):
        invite = self.block("sent", self.msg("INVITE sip:a@b SIP/2.0", "z9hG4bK1", "1 INVITE"))
        busy = self.block("received", self.msg("SIP/2.0 486 Busy Here", "z9hG4bK1", "1 INVITE"))
        good = self.block("sent", self.msg("ACK sip:a@b SIP/2.0", "z9hG4bK1", "1 ACK"))
        bad = self.block("sent", self.msg("ACK sip:a@b SIP/2.0", "z9hG4bK-other", "1 ACK"))
        self.assertEqual(trace.check_hygiene(trace.parse(self.write(invite, busy, good))), [])
        problems = trace.check_hygiene(trace.parse(self.write(invite, busy, bad)))
        self.assertEqual(len(problems), 1)
        self.assertIn("486", problems[0])

    def test_ack_for_success_may_use_a_new_branch(self):
        invite = self.block("sent", self.msg("INVITE sip:a@b SIP/2.0", "z9hG4bK1", "2 INVITE"))
        ok = self.block("received", self.msg("SIP/2.0 200 OK", "z9hG4bK1", "2 INVITE"))
        ack = self.block("sent", self.msg("ACK sip:a@b SIP/2.0", "z9hG4bK-new", "2 ACK"))
        self.assertEqual(trace.check_hygiene(trace.parse(self.write(invite, ok, ack))), [])

    def test_cancel_must_reuse_the_invite_branch(self):
        invite = self.block("sent", self.msg("INVITE sip:a@b SIP/2.0", "z9hG4bK1", "2 INVITE"))
        cancel = self.block("sent", self.msg("CANCEL sip:a@b SIP/2.0", "z9hG4bK2", "2 CANCEL"))
        self.assertEqual(len(trace.check_hygiene(trace.parse(self.write(invite, cancel)))), 1)


class Pcap(unittest.TestCase):
    def test_file_layout(self):
        with tempfile.TemporaryDirectory() as d:
            data = pcap.write_g711a(Path(d) / "a.pcap", packets=10).read_bytes()
        magic, major, minor, _, _, snap, link = struct.unpack("<IHHiIII", data[:24])
        self.assertEqual((magic, link), (0xA1B2C3D4, 1))
        pos, seqs = 24, []
        while pos < len(data):
            sec, usec, caplen, origlen = struct.unpack("<IIII", data[pos:pos + 16])
            frame = data[pos + 16:pos + 16 + caplen]
            self.assertEqual(caplen, origlen)
            self.assertEqual(frame[12:14], b"\x08\x00")  # IPv4
            self.assertEqual(frame[23], 17)  # UDP
            (ip_total,) = struct.unpack("!H", frame[16:18])
            self.assertEqual(ip_total, len(frame) - 14)
            rtp = frame[14 + 20 + 8:]
            self.assertEqual((rtp[0] >> 6, rtp[1] & 0x7F), (2, 8))  # RTP v2, PCMA
            self.assertEqual(len(rtp) - 12, 160)
            seqs.append(struct.unpack("!H", rtp[2:4])[0])
            pos += 16 + caplen
        self.assertEqual(seqs, list(range(10)))


class Ua(unittest.TestCase):
    def test_digest_matches_the_rfc_2617_example(self):
        got = ua.digest_response("Mufasa", "Circle Of Life", "testrealm@host.com", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                                 "GET", "/dir/index.html", "auth", "00000001", "0a4f113b")
        self.assertEqual(got, "6629fae49393a05397450978507c4ef1")

    def test_digest_header_carries_the_challenge_fields(self):
        h = ua.digest_authorization('Digest realm="asterisk",nonce="n1",opaque="o1",algorithm=MD5,qop="auth"',
                                    "101", "pw", "INVITE", "sip:600@127.0.0.1")
        for part in ('username="101"', 'realm="asterisk"', 'nonce="n1"', 'opaque="o1"', "qop=auth", "nc=00000001"):
            self.assertIn(part, h)

    def test_rtp_roundtrip(self):
        pkt = ua.rtp_packet(65537, 12345, 0xABCDEF01, b"xyz")
        self.assertEqual(ua.rtp_parse(pkt), (1, 12345, 0xABCDEF01, b"xyz"))
        self.assertIsNone(ua.rtp_parse(b"short"))
        self.assertIsNone(ua.rtp_parse(b"\x00" * 20))

    def test_reply_parsing(self):
        r = ua.parse_reply(b"SIP/2.0 401 Unauthorized\r\nTo: <sip:a@b>;tag=xyz\r\nCSeq: 1 INVITE\r\n\r\nbody")
        self.assertEqual((r.status, r.reason, r.headers["to"], r.body), (401, "Unauthorized", "<sip:a@b>;tag=xyz", "body"))
        with self.assertRaises(ua.SipError):
            ua.parse_reply(b"HTTP/1.1 200 OK\r\n\r\n")


class Malformed(unittest.TestCase):
    def test_cases_are_distinct_and_deterministic(self):
        a, b = malformed.cases(), malformed.cases()
        self.assertEqual(a, b)
        self.assertEqual(len({n for n, _ in a}), len(a))
        self.assertGreaterEqual(len(a), 30)

    def test_the_well_formed_base_message_is_well_formed(self):
        data = malformed._msg()
        self.assertTrue(data.startswith(b"OPTIONS sip:127.0.0.1 SIP/2.0\r\n"))
        self.assertTrue(data.endswith(b"\r\n\r\n"))


class Reports(unittest.TestCase):
    def sample(self):
        r = report.Report(asterisk="Asterisk 20.6.0", sipp="SIPp v3.7.2")
        r.results = [
            report.CaseResult("a", "does a", "signalling", "passed", 1.5),
            report.CaseResult("b", "does b", "calls", "failed", 2.0, "expected: x\n  wanted: 1\n  got: 2", "log tail"),
            report.CaseResult("c", "does c", "media", "error", 0.1, "Traceback\nboom"),
            report.CaseResult("d", "does d", "media", "skipped", 0, "not today"),
        ]
        return r

    def test_junit_is_valid_and_counts_are_right(self):
        root = ET.fromstring(report.junit(self.sample()))
        self.assertEqual(root.attrib["tests"], "4")
        self.assertEqual((root.attrib["failures"], root.attrib["errors"], root.attrib["skipped"]), ("1", "1", "1"))
        cases = root.findall("testcase")
        self.assertEqual(cases[1].find("failure").attrib["message"], "expected: x")
        self.assertEqual(cases[1].find("system-out").text, "log tail")
        self.assertIsNotNone(cases[2].find("error"))
        self.assertIsNotNone(cases[3].find("skipped"))

    def test_markdown_lists_every_check_and_the_failure_text(self):
        md = report.markdown(self.sample())
        self.assertIn("FAILED", md)
        for name in "abcd":
            self.assertIn(f"`{name}`", md)
        self.assertIn("wanted: 1", md)

    def test_all_passed_headline(self):
        r = report.Report(results=[report.CaseResult("a", "x", "g")])
        self.assertTrue(r.ok)
        self.assertIn("all passed", report.markdown(r))

    def test_junit_escapes_hostile_text(self):
        r = report.Report(results=[report.CaseResult("a", "x", "g", "failed", 0, 'bad <tag> & "quote"', "\x01 ok")])
        ET.fromstring(report.junit(r).replace("\x01", ""))


class LogFilter(unittest.TestCase):
    NOISE = "[Oct 17 13:48:24] WARNING[10432] pjproject: \t       sip_transport.c Dropping 1200 bytes packet"

    def test_sip_stack_complaints_are_fine_only_after_abuse(self):
        self.assertEqual(suite.log_problems(self.NOISE, tolerate_sip_stack=True), [])
        self.assertEqual(len(suite.log_problems(self.NOISE, tolerate_sip_stack=False)), 1)

    def test_other_modules_are_never_tolerated(self):
        line = "[Oct 17 13:48:24] ERROR[101][C-00000001] pbx.c: Unable to find application 'Foo'"
        self.assertEqual(len(suite.log_problems(line, tolerate_sip_stack=True)), 1)

    def test_verbose_and_notice_lines_are_ignored(self):
        text = ("[Oct 17 13:48:24] VERBOSE[1][C-1] pbx.c: Executing [600@internal:1] Answer()\n"
                "[Oct 17 13:48:24] NOTICE[2] res_pjsip/pjsip_distributor.c: Request 'OPTIONS' failed - No matching endpoint")
        self.assertEqual(suite.log_problems(text, tolerate_sip_stack=False), [])

    def test_crash_words_are_caught_anywhere(self):
        for word in ("Segmentation fault", "Assertion failed", "Out of memory"):
            self.assertEqual(len(suite.log_problems(f"[Oct 17 1:1:1] VERBOSE[1] x.c: {word}", True)), 1, word)


class Config(unittest.TestCase):
    def render(self, strict=True):
        d = Path(tempfile.mkdtemp())
        conf = pbx.render(d, 5161, 21000, 21099, "/nonexistent/modules", strict)
        return d, conf

    def test_placeholders_are_all_filled_where_they_belong(self):
        d, _ = self.render()
        for name in ("pjsip.conf", "rtp.conf"):
            text = (d / "etc" / name).read_text()
            self.assertNotIn("${", text, name)
        self.assertIn("bind = 127.0.0.1:5161", (d / "etc" / "pjsip.conf").read_text())
        self.assertIn("rtpstart = 21000", (d / "etc" / "rtp.conf").read_text())

    def test_the_dialplan_keeps_its_own_variables(self):
        d, _ = self.render()
        self.assertIn("${EXTEN}", (d / "etc" / "extensions.conf").read_text())

    def test_strict_rtp_follows_the_switch(self):
        self.assertIn("strictrtp = yes", (self.render(True)[0] / "etc" / "rtp.conf").read_text())
        self.assertIn("strictrtp = no", (self.render(False)[0] / "etc" / "rtp.conf").read_text())

    def test_directories_stay_inside_the_work_dir(self):
        d, conf = self.render()
        text = conf.read_text()
        for key in ("astdbdir", "astspooldir", "astrundir", "astlogdir"):
            self.assertRegex(text, rf"{key} => {re.escape(str(d))}/")

    def test_the_test_pbx_has_no_anonymous_endpoint_and_one_sip_transport(self):
        text = (ROOT / "pbx" / "pjsip.conf").read_text()
        self.assertNotIn("[anonymous]", text)
        self.assertEqual(len(re.findall(r"type\s*=\s*transport", text)), 1)

    def test_hex_addresses(self):
        self.assertEqual(pbx._hex_addr("0100007F"), "127.0.0.1")
        self.assertEqual(pbx._hex_addr("00000000"), "0.0.0.0")
        self.assertEqual(pbx._hex_addr("00000000000000000000000001000000"), "::1")


class Capabilities(unittest.TestCase):
    def test_a_missing_binary_cannot_play_audio_unless_root(self):
        import os
        self.assertEqual(sipp.can_play_pcap("no-such-sipp-binary"), os.geteuid() == 0)

    def test_checks_that_play_audio_are_marked(self):
        marked = {c.name for c in suite.CASES if c.needs_raw}
        self.assertEqual(marked, {"call_echo_test", "call_phone_to_phone"})


class SuiteShape(unittest.TestCase):
    def test_names_are_unique_and_the_health_check_runs_last(self):
        names = [c.name for c in suite.CASES]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[-1], "health_after_everything")
        self.assertGreaterEqual(len(names), 20)

    def test_every_check_has_a_title_and_a_known_group(self):
        for c in suite.CASES:
            self.assertTrue(c.title)
            self.assertIn(c.group, {"signalling", "calls", "media", "robustness", "posture", "health"})

    def test_every_mutant_names_checks_that_exist(self):
        spec = importlib.util.spec_from_file_location("mutants", ROOT / "hack" / "mutants.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        known = {c.name for c in suite.CASES}
        self.assertGreaterEqual(len(mod.MUTANTS), 10)
        for name, _, _, checks, *run in mod.MUTANTS:
            self.assertTrue(set(checks) <= known, name)
            self.assertTrue(set(run[0] if run else []) <= known, name)


if __name__ == "__main__":
    unittest.main()
