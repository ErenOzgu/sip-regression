# Design notes

Why sip-regression is built the way it is. The README says what it checks; this says what was decided and what else was
considered.

## The problem in one paragraph

A PBX change breaks things quietly. A call connects but has no audio. An unknown extension gets a different answer
from a wrong password, which lets an attacker list accounts. A port that should be loopback-only starts listening
everywhere. None of that shows in `asterisk -rx "core reload"`. The aim is a suite that puts a real Asterisk through the
things that go wrong, in about 45 seconds, and says which one broke.

## Decisions

### A real Asterisk, started and thrown away

The suite starts its own Asterisk on loopback in a temporary directory, with its own SIP port (5160), and removes it at
the end. It never touches `/etc/asterisk` or the packaged service. A mock of Asterisk would test the mock; the things
worth knowing here (what the security log says, what a stray BYE gets, what strict RTP does) are what the real program
does. The README's "Things worth knowing" section is a list of such behaviour found by running it, not by reading
documentation.

### SIPp for the protocol, a small Python phone for the rest

SIPp is good at scripted SIP: registrations, calls, error answers, load. It is not good at a phone that both registers
and receives a call (an INVITE has a new Call-ID, so SIPp treats it as an unknown call and answers 603), or at injecting
RTP from the wrong address. So the phone is two SIPp processes where needed, and `ua.py` is a small Python phone for the
digest login and the strict-RTP test. Standard library only: there is nothing to `pip install`.

### Checks look at the wire and at the PBX's own account of it

A check is a SIPp scenario plus questions asked of Asterisk afterwards: contacts, channels, listeners, the security
log. "A wrong password is refused with 401 and shows up in the security log as `ChallengeResponseFailed`" is one check
because the log line is what fail2ban reads. The wire says the refusal happened; the log says it can be acted on.

### The scenarios are checked too

`trace.py` checks that the SIPp scenarios themselves spoke correct SIP. A cancelled call needs the INVITE's branch; a CANCEL
built the obvious way gets `481`, and an ACK with the wrong branch is quietly tolerated, so a scenario can pass while
being wrong. Without a check on the scenario, a green result would not mean much.

### A suite that has never failed proves little

`hack/mutants.py` breaks the test PBX on purpose, one way at a time (an anonymous endpoint, a missing `auth` line,
`strictrtp = no`, AMI on `0.0.0.0`, a catch-all dialplan pattern, an extension that never hangs up, and so on) and runs the
check that should notice. CI runs it and every one of the ten mutants has to be caught.

There is also a control inside the suite: `media_control_loose_rtp_is_detected` boots a second PBX with strict RTP off and
requires the injection to be answered. Without it, "nothing came back" could mean the test never injected anything.

### Skips are visible, and CI does not allow them

The two checks that play audio need `CAP_NET_RAW` for SIPp. Without it they are reported as skipped, with the command to
fix it, and `--require-all` turns a skip into a failure, which is what CI uses.

### Logs are judged, not ignored

A stock Asterisk writes over a hundred warnings while booting (126 on Asterisk 20.6: missing optional `.conf` files), so
the log check starts when Asterisk says it is ready. Hostile input makes the SIP stack write WARNING and ERROR lines;
those are tolerated after `survives_malformed_packets` and only from `pjproject`.

## How it was checked

* Unit tests that need neither Asterisk nor SIPp, on Python 3.10 and 3.13.
* The suite itself, on a real Asterisk: Ubuntu 22.04 (Asterisk 18) and 24.04 (Asterisk 20), with `--require-all`.
* The ten mutants, in CI.
* The scenarios are checked for correct SIP by `trace.py`.

## What would be changed next

See [ROADMAP.md](../ROADMAP.md). The limits in the README are the list: UDP only, one codec family, no SRTP. TCP
transport is first.

## Questions this design usually draws

**Why not test the configuration files?** That is what [asterisk-conf-lint](https://github.com/ErenOzgu/asterisk-conf-lint)
is for. This suite tests behaviour: what the PBX does when it is attacked or misused.

**How do you know a check can fail?** The ten mutants. Each breaks the PBX in one way and names the check that has to
catch it; CI fails if one is missed.

**Why SIPp?** It is the standard tool for scripted SIP and it is what telecom people already know.

**Can I run it against my own PBX?** Yes: `SIPREG_PBX_DIR` points at your templates; the checks assume endpoints 101 and
102 and extensions 600 to 603, and the suite says what is missing.

**Is it a load test?** No. The load checks prove nothing breaks under a burst on one machine, not how many calls a
server can carry.

## Three-minute demo

```sh
sudo apt install asterisk sip-tester python3
sudo systemctl stop asterisk
sudo setcap cap_net_raw+ep "$(readlink -f "$(which sipp)")"
python3 -m sipreg --list
python3 -m sipreg --only register_wrong_password media_ignores_strangers
python3 hack/mutants.py            # the same suite against ten deliberately broken PBXs
```

What to say: the two checks show a refusal that fail2ban can act on, and strict RTP keeping an outsider out of a call. The
mutants run is the point: the suite is only worth trusting because it fails when the PBX is wrong.
