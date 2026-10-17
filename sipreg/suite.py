"""The checks themselves. Each one starts from the same running PBX and states one thing it must do."""
from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import malformed, pcap, sipp, trace
from .pbx import PASSWORDS, Pbx
from .ua import Call, echo_test


class Failure(AssertionError):
    """A check did not hold. The message says what was expected and what happened."""


@dataclass
class Case:
    name: str
    title: str
    group: str
    fn: Callable[[Context], None]
    needs_raw: bool = False  # plays audio with SIPp, which needs root or CAP_NET_RAW


CASES: list[Case] = []


def case(name: str, title: str, group: str = "signalling", needs_raw: bool = False):
    def deco(fn):
        CASES.append(Case(name, title, group, fn, needs_raw))
        return fn
    return deco


# Ports used on loopback. The PBX listens on Context.pbx.sip_port; SIPp uses these.
CALLER_PORT, PHONE_PORT, PHONE_REG_PORT = 5180, 5190, 5191
UA_SIP_PORT, UA_RTP_PORT, OUTSIDER_PORT = 5182, 6002, 6100
PROVISIONAL = re.compile(r"^1\d\d ")


def finals(result: sipp.SippResult) -> list[str]:
    """What the PBX answered, without 1xx lines (a 100 Trying or 180 Ringing may or may not appear)."""
    return [r for r in sipp.responses(result) if not PROVISIONAL.match(r)]


class Context:
    def __init__(self, pbx: Pbx, workdir: Path):
        self.pbx = pbx
        self.workdir = workdir
        self.sipp_dir = workdir / "sipp"
        self.sipp_dir.mkdir(parents=True, exist_ok=True)
        pcap.write_g711a(self.sipp_dir / "g711a.pcap")
        self.boot_mark = pbx.log_mark()
        self.boot_pid = pbx.pid()
        self.boot_rss = pbx.rss_kb()
        self.abused = False  # a check sent the PBX garbage on purpose, so its SIP stack may complain
        self.transcript: list[str] = []

    # -- helpers used by the cases --------------------------------------------------
    def password(self, user: str) -> str:
        return PASSWORDS.get(f"PW_{user}", "not-a-real-password")

    def sipp(self, scenario: str, *, user: str = "101", password: str | None = None, service: str = "600",
             local_port: int = CALLER_PORT, ok: bool = True, **kw) -> sipp.SippResult:
        """Run a scenario, make sure the scenario itself spoke correct SIP, and (by default) that it passed."""
        r = sipp.run(scenario, target_port=self.pbx.sip_port, local_port=local_port, workdir=self.sipp_dir,
                     user=user, password=self.password(user) if password is None else password, service=service, **kw)
        self.transcript.append(r.explain())
        problems = trace.check_hygiene(trace.parse(r.messages))
        if problems:
            raise Failure(f"the scenario {scenario} sent malformed SIP (a test bug, not a PBX bug):\n  "
                          + "\n  ".join(problems))
        if ok and not r.ok:
            raise Failure(r.explain())
        return r

    @contextmanager
    def phone(self, user: str, scenario: str, extra: list[str] | None = None) -> Iterator[sipp.Running]:
        """A SIPp phone: waits for a call at PHONE_PORT, and is registered so the PBX knows where."""
        running = sipp.start(scenario, target_port=self.pbx.sip_port, local_port=PHONE_PORT, workdir=self.sipp_dir,
                             user=user, password=self.password(user), extra=extra)
        try:
            self.sipp("register_ok", user=user, local_port=PHONE_REG_PORT, contact_port=PHONE_PORT,
                      label=f"register_{user}")
            expect(user in self.pbx.contacts(), f"{user} is registered with the PBX")
            yield running
        finally:
            running.stop()
            try:
                self.sipp("unregister", user=user, local_port=PHONE_REG_PORT, ok=False)
            except Exception:
                pass

    def wait_idle(self, timeout: float = 8.0) -> None:
        """Wait for every channel to be gone; a call that is still there afterwards is a leak."""
        deadline = time.time() + timeout
        n = self.pbx.active_channels()
        while n and time.time() < deadline:
            time.sleep(0.25)
            n = self.pbx.active_channels()
        expect(n == 0, f"no channel left behind (found {n} after {timeout:.0f} s)")

    def security_events(self, mark: int, kind: str, account: str) -> int:
        text = self.pbx.security_log()[mark:]
        return len(re.findall(rf'SecurityEvent="{kind}".*?AccountID="{re.escape(account)}"', text))


def expect(condition: bool, what: str) -> None:
    if not condition:
        raise Failure("expected: " + what)


def expect_equal(actual, wanted, what: str) -> None:
    if actual != wanted:
        raise Failure(f"{what}\n  wanted: {wanted!r}\n  got:    {actual!r}")


# =========================================================================== registration
@case("register_with_password", "a phone that knows its password registers, and unregisters again")
def _(ctx: Context) -> None:
    ctx.sipp("register_ok")
    expect("101" in ctx.pbx.contacts(), "endpoint 101 has a contact after REGISTER")
    ctx.sipp("unregister")
    expect("101" not in ctx.pbx.contacts(), "endpoint 101 has no contact after REGISTER with Expires: 0")


@case("register_wrong_password", "a wrong password is refused and shows up as a security event")
def _(ctx: Context) -> None:
    mark = len(ctx.pbx.security_log())
    r = ctx.sipp("register_bad_password", password="definitely-wrong")
    expect_equal(finals(r), ["401 Unauthorized", "401 Unauthorized"], "answers to a wrong password")
    expect("101" not in ctx.pbx.contacts(), "no contact is stored for a refused REGISTER")
    expect(ctx.security_events(mark, "ChallengeResponseFailed", "101") >= 1,
           "a ChallengeResponseFailed security event for account 101 (this is the line fail2ban reads)")


@case("register_unknown_user", "an unknown user gets the same answers as a wrong password, so accounts cannot be guessed")
def _(ctx: Context) -> None:
    mark = len(ctx.pbx.security_log())
    wrong = ctx.sipp("register_bad_password", password="definitely-wrong")
    unknown = ctx.sipp("register_bad_password", user="9999", password="whatever")
    expect_equal(finals(unknown), finals(wrong), "answers to an unknown user and to a wrong password")
    expect(ctx.security_events(mark, "InvalidAccountID", "9999") >= 1,
           "an InvalidAccountID security event for account 9999")


@case("options_needs_credentials", "OPTIONS from a stranger is challenged; from a user with a password it gets 200")
def _(ctx: Context) -> None:
    r = ctx.sipp("options_anonymous", user="stranger", password="")
    expect_equal(finals(r), ["401 Unauthorized"], "answer to an anonymous OPTIONS")
    r = ctx.sipp("options_authenticated")
    expect_equal(finals(r), ["401 Unauthorized", "200 OK"], "answers to an authenticated OPTIONS")


# =========================================================================== calls: refusals
@case("invite_without_credentials", "an INVITE with no password is answered 401 and never reaches the dialplan")
def _(ctx: Context) -> None:
    mark = ctx.pbx.log_mark()
    for user in ("101", "9999"):
        r = ctx.sipp("invite_unauthenticated", user=user, password="")
        expect_equal(finals(r), ["401 Unauthorized"], f"answers to an unauthenticated INVITE from {user}")
    expect("Executing [600@internal" not in ctx.pbx.log_since(mark), "the echo extension was never executed")
    ctx.wait_idle()


@case("invite_unknown_extension", "a logged-in phone dialling a number nothing handles gets 404")
def _(ctx: Context) -> None:
    r = ctx.sipp("invite_unknown_extension", service="699")
    expect_equal(finals(r), ["401 Unauthorized", "404 Not Found"], "answers")
    ctx.wait_idle()


@case("invite_busy", "an extension that answers Busy() gives the caller 486")
def _(ctx: Context) -> None:
    r = ctx.sipp("invite_busy", service="602")
    expect_equal(finals(r), ["401 Unauthorized", "486 Busy Here"], "answers")
    ctx.wait_idle()


@case("invite_congestion", "an extension that answers Congestion() gives the caller 503")
def _(ctx: Context) -> None:
    r = ctx.sipp("invite_congestion", service="603")
    expect_equal(finals(r), ["401 Unauthorized", "503 Service Unavailable"], "answers")
    ctx.wait_idle()


@case("bye_for_unknown_call", "a BYE for a call that does not exist is answered, not ignored")
def _(ctx: Context) -> None:
    r = ctx.sipp("bye_unknown_dialog")
    expect(finals(r) in (["481 Call/Transaction Does Not Exist"], ["401 Unauthorized"]),
           f"481 (or a challenge), got {finals(r)}")


# =========================================================================== calls: completed
@case("call_echo_test", "a call to the echo extension is answered, carries RTP for 3 s and ends cleanly", "calls",
      needs_raw=True)
def _(ctx: Context) -> None:
    r = ctx.sipp("invite_echo", service="600")
    expect_equal(finals(r), ["401 Unauthorized", "200 OK", "200 OK"], "answers (the last 200 is for the BYE)")
    ctx.wait_idle()


@case("call_ended_by_pbx", "when the PBX hangs up it sends a BYE the phone can answer", "calls")
def _(ctx: Context) -> None:
    ctx.sipp("invite_pbx_hangs_up", service="601")
    ctx.wait_idle()


@case("call_hold_and_resume", "re-INVITEs for hold and resume are accepted and the call survives them", "calls")
def _(ctx: Context) -> None:
    r = ctx.sipp("invite_reinvite", service="600")
    expect_equal(finals(r), ["401 Unauthorized"] + ["200 OK"] * 4, "answers (INVITE, hold, resume, BYE)")
    ctx.wait_idle()


@case("call_phone_to_phone", "101 calls 102: the PBX rings the registered phone, bridges the call and relays the hang-up",
      "calls", needs_raw=True)
def _(ctx: Context) -> None:
    with ctx.phone("102", "phone_answers", extra=["-rtp_echo"]) as phone:
        r = ctx.sipp("invite_echo", service="102")
        callee = phone.finish()
        expect(callee.ok, "the called phone saw a normal call:\n" + callee.explain())
    expect_equal(finals(r), ["401 Unauthorized", "200 OK", "200 OK"], "answers to the caller")
    ctx.wait_idle()


@case("call_cancelled_while_ringing", "a caller who gives up gets 487, the ringing phone sees the CANCEL, nothing stays up",
      "calls")
def _(ctx: Context) -> None:
    with ctx.phone("102", "phone_rings") as phone:
        r = ctx.sipp("invite_cancel", service="102")
        callee = phone.finish()
        expect(callee.ok, "the ringing phone saw the CANCEL and refused with 487:\n" + callee.explain())
    expect_equal(finals(r), ["401 Unauthorized", "200 OK", "487 Request Terminated"], "answers to the caller")
    ctx.wait_idle()


# =========================================================================== media
def _ua_call(ctx: Context, **kw) -> Call:
    call = Call(pbx_port=ctx.pbx.sip_port, user="101", password=ctx.password("101"), extension="600",
                sip_port=UA_SIP_PORT, rtp_port=UA_RTP_PORT, **kw)
    call.open()
    reply = call.invite()
    expect(reply.status == 200, f"the echo call is answered, got {reply.status} {reply.reason}")
    return call


@case("media_is_echoed", "audio sent into the echo test comes back intact and in order", "media")
def _(ctx: Context) -> None:
    call = _ua_call(ctx)
    try:
        res = echo_test(call, packets=100)
        expect(res.intact >= 95, f"at least 95 of 100 packets come back intact, got {res.intact} ({res})")
        expect(res.in_order, "the packets come back in the order they were sent")
        expect_equal(call.bye().status, 200, "answer to BYE")
    finally:
        call.close()
    ctx.wait_idle()


@case("media_ignores_strangers", "strict RTP: packets from an address that is not in the call are dropped and never answered",
      "media")
def _(ctx: Context) -> None:
    call = _ua_call(ctx)
    try:
        res = echo_test(call, packets=100, inject_from=OUTSIDER_PORT)
        expect(res.foreign_sent > 100, "the outsider really sent packets")
        expect_equal(res.injected_back, 0, "RTP packets sent back to an outsider who injected audio")
        expect(res.intact >= 95, f"the real call is not disturbed by the injection ({res.intact} of 100 intact)")
        call.bye()
    finally:
        call.close()
    ctx.wait_idle()


@case("media_control_loose_rtp_is_detected",
      "control: with strict RTP switched off the same injection IS answered, so the check above can fail", "media")
def _(ctx: Context) -> None:
    loose = Pbx(ctx.workdir / "loose", sip_port=ctx.pbx.sip_port + 1, rtp_start=21000, rtp_end=21199,
                binary=ctx.pbx.binary, strict_rtp=False)
    loose.start()
    try:
        call = Call(pbx_port=loose.sip_port, user="101", password=ctx.password("101"), extension="600",
                    sip_port=UA_SIP_PORT, rtp_port=UA_RTP_PORT)
        call.open()
        try:
            expect(call.invite().status == 200, "the echo call on the control PBX is answered")
            res = echo_test(call, packets=100, inject_from=OUTSIDER_PORT)
            expect(res.injected_back > 0, "the outsider is answered when strict RTP is off "
                   f"(it was not: {res}), so the injection check would not have noticed")
            call.bye()
        finally:
            call.close()
    finally:
        loose.stop()


# =========================================================================== robustness and load
@case("survives_malformed_packets", "35 broken and hostile datagrams, then a 1000-INVITE flood: still up, still answering",
      "robustness")
def _(ctx: Context) -> None:
    ctx.abused = True
    outcomes = malformed.send_all(ctx.pbx.sip_port)
    bad = [o for o in outcomes if o.answered is not None and 200 <= o.answered < 300]
    expect(not bad, "no broken request is answered with a success: " + ", ".join(o.name for o in bad))
    malformed.flood(ctx.pbx.sip_port, 1000)
    time.sleep(1.5)
    expect(ctx.pbx.alive() and ctx.pbx.pid() == ctx.boot_pid, "Asterisk is still the same running process")
    r = ctx.sipp("options_anonymous", user="stranger", password="")
    expect_equal(finals(r), ["401 Unauthorized"], "the PBX still answers a normal request")
    ctx.wait_idle()


@case("load_registrations", "300 registrations at 100 per second all succeed", "robustness")
def _(ctx: Context) -> None:
    r = ctx.sipp("register_ok", calls=300, rate=100, max_concurrent=100, timeout=60)
    expect(r.failed == 0 and r.calls >= 300, f"300 registrations without failure: {r.explain()}")
    ctx.sipp("unregister")


@case("load_calls", "200 short calls at 25 per second all complete, leave no channel behind and no memory growth",
      "robustness")
def _(ctx: Context) -> None:
    rss_before = ctx.pbx.rss_kb()
    r = ctx.sipp("invite_pbx_hangs_up", service="601", calls=200, rate=25, max_concurrent=80, timeout=90)
    expect(r.failed == 0 and r.calls >= 200, f"200 calls without failure: {r.explain()}")
    ctx.wait_idle(timeout=15)
    growth = ctx.pbx.rss_kb() - rss_before
    expect(growth < 100_000, f"resident memory grew by {growth // 1024} MB over 200 calls (limit 100 MB)")


# =========================================================================== posture
@case("listens_only_where_expected", "the only open port is SIP on the loopback address: no AMI, HTTP, IAX or second SIP stack",
      "posture")
def _(ctx: Context) -> None:
    ctx.wait_idle()
    wanted = [f"udp 127.0.0.1:{ctx.pbx.sip_port}"]
    expect_equal(ctx.pbx.listeners(), wanted, "sockets Asterisk is listening on")


# =========================================================================== health (always last)
@case("health_after_everything", "same process, no calls left, and no warning or error in the log that the tests did not cause",
      "health")
def _(ctx: Context) -> None:
    pbx = ctx.pbx
    expect(pbx.alive(), "Asterisk is running")
    expect(pbx.pid() == ctx.boot_pid, "it is the process that was started (no crash and restart)")
    ctx.wait_idle()
    problems = log_problems(pbx.log_since(ctx.boot_mark), tolerate_sip_stack=ctx.abused)
    expect(not problems, "no unexpected WARNING/ERROR in the log:\n  " + "\n  ".join(problems[:15]))


ENTRY = re.compile(r"^\[[A-Z][a-z]{2} +\d+ [\d:]+\] (\w+)\[\d+\](?:\[[^\]]*\])? ([^:]+):")
CRASH = re.compile(r"segmentation fault|SIGSEGV|assertion|ASSERT|abort\(|out of memory|deadlock|double free",
                   re.I)


def log_problems(text: str, tolerate_sip_stack: bool) -> list[str]:
    """WARNING/ERROR entries that should not be there. The SIP stack (pjproject) complains
    about broken input; that is expected after the robustness check and nowhere else."""
    out: list[str] = []
    for line in text.splitlines():
        if CRASH.search(line):
            out.append(line.strip()[:200])
            continue
        m = ENTRY.match(line)
        if not m or m.group(1) not in ("WARNING", "ERROR"):
            continue
        if tolerate_sip_stack and m.group(2).strip() == "pjproject":
            continue
        out.append(line.strip()[:200])
    return out
