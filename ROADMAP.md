# Roadmap

Small steps, in order. A step is done when it has tests, the README says what changed, CI is green and the CHANGELOG
has a line for it. A check that is added also gets a mutant in `hack/mutants.py` that it has to catch. Each step is
meant to be a few hours of work, not a rewrite.

- [ ] `invite_no_common_codec`: an INVITE whose SDP offers only a codec the PBX does not allow gets `488`, and a mutant
      that allows every codec
- [ ] `register_over_tcp`: a loopback TCP transport in the test PBX and a registration over it (SIPp `-t t1`)
- [ ] `call_over_tcp`: a call over the same transport
- [ ] `max_contacts`: a second registration from the same endpoint replaces the first when `remove_existing` is set,
      and a mutant that lets contacts pile up
- [ ] `--list --json`: the checks as JSON, for tools
- [ ] A first release (`v0.1.0`) with a release workflow, like the other repositories have
- [ ] SRTP, if the packaged Asterisk has `res_srtp`; otherwise say so in the limits
