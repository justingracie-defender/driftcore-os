# SPDX-License-Identifier: Apache-2.0
"""
test_audience_release.py — a room is cleared by who is in it when a draft is
released, and nothing is held unless the wall labelled it.

# CLAIMS: driftcore/governance/audience_release.py:release-follows-the-current-room
# CLAIMS: driftcore/governance/audience_release.py:future-members-count-where-history-shows
# CLAIMS: driftcore/governance/audience_release.py:unreadable-roster-refuses
# CLAIMS: driftcore/governance/audience_release.py:unregistered-member-is-public
# CLAIMS: driftcore/governance/audience_release.py:stale-roster-refuses
# CLAIMS: driftcore/governance/audience_release.py:one-minting-path
# CLAIMS: driftcore/governance/audience_release.py:drafter-is-registered
# CLAIMS: driftcore/governance/audience_release.py:draft-label-is-assigned-by-the-wall
# CLAIMS: driftcore/governance/audience_release.py:drafter-sees-only-what-the-room-may-hold
# CLAIMS: driftcore/governance/audience_release.py:tainted-brief-refuses
# CLAIMS: driftcore/governance/audience_release.py:agent-draft-carries-session-label
# CLAIMS: driftcore/governance/audience_release.py:text-committed-per-ticket
# CLAIMS: driftcore/governance/audience_release.py:exact-bytes-once
# CLAIMS: driftcore/governance/audience_release.py:human-release-binds-the-audience
# CLAIMS: driftcore/governance/audience_release.py:disclosure-needs-authority
# CLAIMS: driftcore/governance/audience_release.py:join-floor-needs-a-human
# CLAIMS: driftcore/governance/audience_release.py:floor-breach-is-not-a-routine-refusal
# CLAIMS: driftcore/governance/audience_release.py:post-send-change-is-recorded
# CLAIMS: driftcore/governance/audience_release.py:sender-must-accept
# CLAIMS: driftcore/governance/audience_release.py:unrecorded-release-refuses
# CLAIMS: driftcore/governance/audience_release.py:spent-drafts-are-disposed
# CLAIMS: driftcore/governance/audience_release.py:review-shows-exposure
# CLAIMS: driftcore/governance/audience_release.py:audit-names-the-audience-not-the-content

Sections A-K are the v133 checks, carried into v134 through the only doors it
leaves open: an agent's words through its session (put() below does exactly that),
and drafters registered when the gate is built. Their names are unchanged.

Section L is the v133 red team (Grok and Astra, 2026-09-11). Every finding was
reproduced against v133 before any change, and each check names the finding it
covers. Three checks are marked RESIDUAL: they pass by showing that a limit sits
exactly where the module says it does, not that it is closed.

Section I replays test_redteam_audience_rebind.py through the gate: the live
rebind (C), history visible to new members (D), and the rewrite loop that was
dropped from the design. The red-team file still passes, because its probes
target FlowController, which this gate sits in front of rather than replaces.

MUTATION CHECK (2026-09-10, against v132 plus this module)
  22 single mutations, at least one per claim, each disabling one mechanism in a
  scratch copy. The runner refuses to count a mutation whose anchor does not match
  exactly once. All 22 turn their named checks red. Two first died only by crashing
  in another layer: a bare value hit an AttributeError, and a self-labelled draft
  was stopped by information_flow's freeze. That is incidental containment, so
  those checks now pass only on the gate's own BuildRefused. Replay C is held by
  two independent mechanisms: turning off the stale check or the release label
  check alone leaves it green, and turning off both turns it red.

  Rerun 2026-09-11 after adding sessions and fixing three error paths: 31 single
  mutations plus the double, all killed. The rewrite-loop replay and the
  tainted-brief check used to set SECRET_FAMILY on the agent's words by hand, so
  what held the paraphrase was the test author rather than the wall. Both now go
  through AgentSession.

MUTATION CHECK (2026-09-11, v134, scripts/mutate_audience_release.py)
  54 single mutations, at least one per claim and at least one per red-team finding
  repaired below, all KILLED on the checks they name. Four protections are held by
  more than one mechanism: each of their 9 parts survives alone, as expected, and
  each combination kills.

  One anchor went stale when the expiry comparison was rewritten to prove its
  operands finite, and the runner reported DID NOT APPLY rather than a pass. That
  guard had no check of its own until then, so a NaN clock is now a check rather
  than a habit — and the mutation showed that removing the isfinite call alone
  changes nothing, because what actually makes a non-finite clock safe is the
  POLARITY of the age test: NaN is false against every comparison, and "not young"
  is the branch that drops the draft. Write the same test as `not (age > cap)` and
  NaN keeps the secret in memory instead. Both are in the redundancy list, and
  removing either alone leaves the check green.

  The first run of this list reported M10 as a survivor that was not one. CPython
  invalidates a cached .pyc by the source's mtime in whole SECONDS and its size in
  bytes, and M9b and M10 produce sources of identical length and run back to back,
  so M10 ran M9b's bytecode and was scored against M9b's red check. Eight pairs in
  that list collide on length. The runner now runs its subprocesses with bytecode
  writing off, clears any cache first, and re-reads the file before launching. A
  mutation runner that silently tests the previous mutation is worse than no
  mutation runner, because it reports coverage that does not exist.

Run: python3 test_audience_release.py
"""
import dataclasses, gc, hashlib, math, sys, warnings; sys.path.insert(0, ".")
import driftcore.authority.human_identity as hid
import driftcore.governance.audience_release as ar
from driftcore.governance.information_flow import (
    FlowRefused, Level, Label, Labeled, LabeledSource, PUBLIC)
from driftcore.governance.audience_release import (
    AgentSession, AudienceGate, BuildRefused, DraftContext, Drafter, Outcome,
    RoomDeclaration, Roster, join_floor_action, label_token, _label_parts)

EXPECTED_CHECKS = 115

P = []
def ck(n, c): P.append(bool(c)); print(f"  [{'PASS' if c else 'FAIL'}] {n}")


SECRET_FAMILY = Label(Level.SECRET, frozenset({"family"}))
INTERNAL = Label(Level.INTERNAL)
CLEAR = {"parent_a": SECRET_FAMILY, "parent_b": SECRET_FAMILY,
         "grandma": SECRET_FAMILY, "george": INTERNAL, "guest": PUBLIC}
FAMILY = {"parent_a", "parent_b"}
PLATFORM = "test-platform"


class Platform:
    # Stand-in for a chat service. It owns rooms, rosters and delivery; the gate
    # only ever reads the roster and calls send.
    def __init__(self):
        self.rooms, self.delivered, self.down = {}, [], set()
        self.wrong_room, self.during_send, self.source = {}, None, PLATFORM
    def make(self, room, members, history=False):
        self.rooms[room] = {"members": set(members), "history": history, "epoch": 1}
    def add(self, room, who, bump=True):
        self.rooms[room]["members"].add(who)
        if bump:
            self.rooms[room]["epoch"] += 1
    def leave(self, room, who, bump=True):
        self.rooms[room]["members"].discard(who)
        if bump:
            self.rooms[room]["epoch"] += 1
    def roster(self, room):
        if room in self.down:
            raise ConnectionError("platform unavailable")
        r = self.rooms[self.wrong_room.get(room, room)]
        return Roster(room=self.wrong_room.get(room, room),
                      members=frozenset(r["members"]), history_visible=r["history"],
                      epoch=r["epoch"], source=self.source)
    def send(self, room, value):
        self.delivered.append((room, value))
        if self.during_send:
            self.during_send()
        return True
    def to(self, room):
        return [v for (r, v) in self.delivered if r == room]


class _Audit:
    # Returns a receipt per record, as driftcore.audit.record() returns the entry
    # it wrote. fail_on raises for one action; none_on returns None for it, which
    # is how the real audit module reports a failed or compromised write.
    def __init__(self, fail_on=None, none_on=None):
        self.records, self.fail_on, self.none_on = [], fail_on, none_on
    def record(self, **kw):
        if self.fail_on is not None and kw.get("action") == self.fail_on:
            raise OSError("audit disk full")
        if self.none_on is not None and kw.get("action") == self.none_on:
            return None
        self.records.append(kw)
        return {"sequence": len(self.records), **kw}


def _drafter(fn, name):
    return Drafter(fn, AgentSession(f"drafter-{name}", readable=[PUBLIC]))
DRAFTERS = {
    "echo": _drafter(lambda parts: " | ".join(parts), "echo"),
    "calm": _drafter(lambda parts: "nothing to see here", "calm"),
    "self-label": _drafter(lambda parts: Labeled.public("trust me"), "self-label"),
    "late": _drafter(lambda parts: "running late, " + parts[-1], "late"),
}


def gate(pf, audit=None, declarations=(), drafters=None, disclosers=("parent_a",), **kw):
    return AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=pf.roster,
                        send_fn=pf.send, audit=audit if audit is not None else _Audit(),
                        declarations=declarations,
                        drafters=DRAFTERS if drafters is None else drafters,
                        disclosers=disclosers, **kw)


_agent = [0]
def put(g, room, item):
    # Hold item's text at exactly item's label, through the one door an agent has.
    _agent[0] += 1
    sid = g.open_session(f"agent-{_agent[0]}", readable=[item.label])
    return g.hold_agent_draft(room, sid, item.value)


def refuses_flow(fn):
    # True only for the gate's own FlowRefused. Anything else is incidental.
    try:
        fn()
    except FlowRefused:
        return True
    except Exception:
        return False
    return False


def refuses(fn):
    # True only for the gate's own refusal. An AttributeError, or a refusal from
    # another layer, would be incidental containment: something else stopped it.
    try:
        fn()
    except BuildRefused:
        return True
    except Exception:
        return False
    return False


household = LabeledSource("memory:household", SECRET_FAMILY,
    lambda: "spare key under the blue planter; kids home alone Tue/Thu 3-5pm")
SECRET = household.read()
SECRET_VALUE = SECRET.value
SCHED = LabeledSource("calendar:shared", INTERNAL,
                      lambda: "pickup moved to 4pm Thursday").read()
HELLO = Labeled.public("see you at dinner")
BRIEF = Labeled.public("reply to the latest message in this room", origin="room:latest")

# The weakest mode a process can be in, where is_human accepts a bare name, has to
# be probed before any verifier is installed: human_identity refuses to downgrade
# an ATTESTED process to label-only, which is right. The result is checked in G.
_pf0 = Platform(); _pf0.make("hum0", FAMILY | {"george"}); _g0 = gate(_pf0)
_d0 = put(_g0, "hum0", SECRET)
hid.reset_policy()
hid.declare_label_only("test suite: bare-name probe; nothing real is sent")
_bare = _g0.release_by_human(_d0.ticket, "parent_a", "george is picking up the kids")
BARE_NAME_REFUSED = _bare.outcome is Outcome.REFUSED_HUMAN and _pf0.to("hum0") == []

hid.reset_policy()
KEY = b"parent-a-device-key-0123456789abcdef"
GUEST_KEY = b"guest-device-key-0123456789abcdef!!"
v = hid.HumanIdentityVerifier()
v.register_principal("parent_a", KEY); v.register_principal("guest", GUEST_KEY)
hid.set_verifier(v)
_nonce = [0]
def attest(action, key=KEY, who="parent_a"):
    _nonce[0] += 1
    return hid.HumanAttestation.issue(key, principal=who, action=action,
                                      ttl_seconds=300, nonce=f"n{_nonce[0]}")
def floor(room, label, who="parent_a", key=KEY):
    return RoomDeclaration(room, label, declared_by=who,
                           attestation=attest(join_floor_action(PLATFORM, room, label),
                                              key, who))




print("\nA. The room decides, read at release time")
pf = Platform(); pf.make("fam", FAMILY); g = gate(pf)
d = put(g, "fam", SECRET); r = g.release(d.ticket)
ck("family-only room: SECRET+{family} is HELD and RELEASED to the family",
   d.outcome is Outcome.HELD and r.outcome is Outcome.RELEASED
   and pf.to("fam") == [SECRET_VALUE])
pf.make("gfam", FAMILY | {"george"})
d = put(g, "gfam", SECRET); r = g.release(d.ticket)
ck("george in the room: held for a human, automatic release REFUSED, nothing sent",
   d.outcome is Outcome.HELD_FOR_HUMAN and r.outcome is Outcome.REFUSED_LABEL
   and pf.to("gfam") == [])
pf.make("quiet", FAMILY)
# A cleared member, so only the roster binding can catch it, not the label check.
d = put(g, "quiet", SECRET); pf.add("quiet", "grandma", bump=False); r = g.release(d.ticket)
ck("a member added WITHOUT an epoch change is still caught: REFUSED_STALE",
   r.outcome is Outcome.REFUSED_STALE and pf.to("quiet") == [])
pf.make("strange", FAMILY | {"stranger"})
d1 = put(g, "strange", SECRET); d2 = put(g, "strange", HELLO)
ck("an unregistered member counts as PUBLIC: SECRET is held for a human",
   d1.outcome is Outcome.HELD_FOR_HUMAN)
ck("the same room still takes PUBLIC, so the rule is not refuse-all",
   g.release(d2.ticket).outcome is Outcome.RELEASED and pf.to("strange") == [HELLO.value])

print("\nB. History visible to new members, and the join floor")
pf.make("hist", FAMILY, history=True)
d = put(g, "hist", SECRET)
ck("history-visible room, no declaration: SECRET is not auto-releasable (floor PUBLIC)",
   d.outcome is Outcome.HELD_FOR_HUMAN and g.release(d.ticket).outcome is Outcome.REFUSED_LABEL)
d = put(g, "hist", HELLO)
ck("the same room still takes PUBLIC",
   g.release(d.ticket).outcome is Outcome.RELEASED and pf.to("hist") == [HELLO.value])
pf.make("decl", FAMILY, history=True)
audit_b = _Audit()
gb = gate(pf, audit_b, [floor("decl", SECRET_FAMILY)])
d = put(gb, "decl", SECRET)
ck("with a declared floor of SECRET+{family}, SECRET is released",
   gb.release(d.ticket).outcome is Outcome.RELEASED and pf.to("decl") == [SECRET_VALUE])
pf.add("decl", "george")
d = put(gb, "decl", HELLO)
ck("george added below the declared floor: its own outcome, not a label refusal",
   d.outcome is Outcome.REFUSED_FLOOR_BREACH and d.ticket is None)
actions_b = [x["action"] for x in audit_b.records]
ck("the floor breach is recorded under its own name",
   "AUDIENCE_REFUSED_FLOOR_BREACH" in actions_b and "AUDIENCE_REFUSED_LABEL" not in actions_b)

print("\nC. Rosters that cannot be trusted")
pf.make("down", FAMILY); pf.down.add("down")
d = put(g, "down", HELLO)
ck("a roster read that raises: REFUSED_ROSTER, no ticket, nothing sent",
   d.outcome is Outcome.REFUSED_ROSTER and d.ticket is None and pf.to("down") == [])
pf.make("empty", set())
ck("a roster naming no members: REFUSED_ROSTER",
   put(g, "empty", HELLO).outcome is Outcome.REFUSED_ROSTER)
pf.make("liar", FAMILY); pf.wrong_room["liar"] = "fam"
ck("a reader answering for a different room: REFUSED_ROSTER",
   put(g, "liar", HELLO).outcome is Outcome.REFUSED_ROSTER)
pf.make("flaky", FAMILY)
d = put(g, "flaky", HELLO); pf.down.add("flaky"); r1 = g.release(d.ticket)
pf.down.discard("flaky"); r2 = g.release(d.ticket)
ck("unreadable at release: refused, ticket kept, released once readable again",
   r1.outcome is Outcome.REFUSED_ROSTER and r2.outcome is Outcome.RELEASED
   and pf.to("flaky") == [HELLO.value])

print("\nD. Delivery bound to the audience that was checked")
pf.make("move", FAMILY)
d = put(g, "move", SECRET); pf.add("move", "grandma"); r = g.release(d.ticket)
ck("roster changed to a FULLY cleared one: still REFUSED_STALE, nothing sent",
   r.outcome is Outcome.REFUSED_STALE and pf.to("move") == [])
d2 = put(g, "move", SECRET)
ck("held again against the new roster, it releases",
   g.release(d2.ticket).outcome is Outcome.RELEASED and pf.to("move") == [SECRET_VALUE])
pf.make("race", FAMILY); audit_d = _Audit(); gd = gate(pf, audit_d)
d = put(gd, "race", HELLO)
pf.during_send = lambda: pf.add("race", "george")
r = gd.release(d.ticket); pf.during_send = None
acts = [x["action"] for x in audit_d.records]
ck("a join during delivery: RELEASED_ROSTER_MOVED, with its own record",
   r.outcome is Outcome.RELEASED_ROSTER_MOVED
   and "AUDIENCE_RELEASED_ROSTER_MOVED" in acts and "AUDIENCE_RELEASED" not in acts)

print("\nE. The clean drafter")
ctx = g.build_context("gfam", BRIEF, [SECRET, SCHED, HELLO])
ck("context for george's room holds only what the room may hold (secret withheld)",
   ctx.items == (SCHED, HELLO) and ctx.withheld == 1)
de = g.hold_clean_draft(ctx, "echo"); echo = g.review(de.ticket)
ck("a drafter that echoes everything it saw cannot echo the secret",
   SECRET_VALUE not in echo["value"] and "planter" not in echo["value"])
ck("a bare candidate refuses the build instead of being guessed at",
   refuses(lambda: g.build_context("gfam", BRIEF, [SECRET_VALUE])))
saw_it = AgentSession("agent-e", readable=[SECRET_FAMILY])
ck("a brief from the session that saw the secret refuses the whole build",
   refuses(lambda: g.build_context("gfam", saw_it.labelled("tell george where the key is"),
                                   [SCHED])))
fctx = g.build_context("fam", BRIEF, [SECRET])
calm = g.review(g.hold_clean_draft(fctx, "calm").ticket)
ck("the wall labels the draft by what went in, whatever the drafter says",
   calm["label"] == str(SECRET_FAMILY) and "memory:household" in calm["origins"])
ck("a drafter handing back its own label is refused",
   refuses(lambda: g.hold_clean_draft(fctx, "self-label")))
r = g.release(de.ticket)
ck("the clean draft releases automatically to george's room",
   de.outcome is Outcome.HELD and r.outcome is Outcome.RELEASED
   and pf.to("gfam") == [echo["value"]])

print("\nF. Exact bytes, once")
pf.make("once", FAMILY)
d = put(g, "once", SECRET); r1 = g.release(d.ticket)
ck("what was sent is exactly what was held, sent once",
   r1.sent and pf.to("once") == [SECRET_VALUE])
ck("a second release of the same ticket: REFUSED_SPENT, nothing more sent",
   g.release(d.ticket).outcome is Outcome.REFUSED_SPENT and len(pf.to("once")) == 1)
pf.make("again", FAMILY); inner = []
d = put(g, "again", HELLO)
def _release_again_once():
    pf.during_send = None
    inner.append(g.release(d.ticket))
pf.during_send = _release_again_once
r = g.release(d.ticket); pf.during_send = None
ck("a release attempted while the same ticket is being sent is refused",
   r.sent and len(inner) == 1 and inner[0].outcome is Outcome.REFUSED_SPENT
   and pf.to("again") == [HELLO.value])

print("\nG. Human release: an attestation for this ticket, room, draft and roster")
spent = d.ticket
pf.make("hum", FAMILY | {"george"}); audit_g = _Audit(); gh = gate(pf, audit_g)
d = put(gh, "hum", SECRET)
ck("even in a label-only process, a bare name releases nothing", BARE_NAME_REFUSED)
ck("a human release of a spent ticket: REFUSED_SPENT",
   g.release_by_human(spent, attest("anything"), "late approval").outcome
   is Outcome.REFUSED_SPENT)
rv = gh.review(d.ticket)
wrong = rv["action"].replace(rv["digest"], "0" * len(rv["digest"]))
r = gh.release_by_human(d.ticket, attest(wrong), "george is picking up the kids")
ck("an attestation for a different draft releases nothing",
   r.outcome is Outcome.REFUSED_HUMAN and pf.to("hum") == [])
a_ok = attest(rv["action"])
r = gh.release_by_human(d.ticket, a_ok, "george is picking up the kids")
rec = [x for x in audit_g.records if x["action"] == "AUDIENCE_RELEASED"]
ck("an attestation naming this ticket, room, digest and roster releases, recorded as parent_a",
   r.outcome is Outcome.RELEASED and pf.to("hum") == [SECRET_VALUE]
   and rec and rec[-1]["authorised_by"] == "parent_a")
d2 = put(gh, "hum", SECRET)
ck("the same attestation replayed on a new ticket releases nothing",
   gh.release_by_human(d2.ticket, a_ok, "again").outcome is Outcome.REFUSED_HUMAN
   and len(pf.to("hum")) == 1)
rv2 = gh.review(d2.ticket); a_new = attest(rv2["action"]); pf.add("hum", "grandma")
ck("the roster changed after the human signed: REFUSED_STALE",
   gh.release_by_human(d2.ticket, a_new, "approved").outcome is Outcome.REFUSED_STALE
   and len(pf.to("hum")) == 1)
d3 = put(gh, "hum", SECRET)
ck("a reason that is not a one-line justification releases nothing",
   gh.release_by_human(d3.ticket, attest(gh.review(d3.ticket)["action"]),
                       "ok\nAUDIENCE_RELEASED forged").outcome is Outcome.REFUSED_HUMAN
   and len(pf.to("hum")) == 1)

print("\nH. Records")
pf.make("rec", FAMILY)
gx = gate(pf, _Audit(fail_on="AUDIENCE_HELD"))
d = put(gx, "rec", HELLO)
ck("the hold record cannot be written: REFUSED_UNRECORDED, no ticket",
   d.outcome is Outcome.REFUSED_UNRECORDED and d.ticket is None)
gy = gate(pf, _Audit(fail_on="AUDIENCE_RELEASING"))
d = put(gy, "rec", HELLO); r = gy.release(d.ticket)
ck("the release record cannot be written: REFUSED_UNRECORDED, nothing sent",
   r.outcome is Outcome.REFUSED_UNRECORDED and pf.to("rec") == [])
pf.make("fp", FAMILY); audit_h = _Audit(); gz = gate(pf, audit_h)
gz.release(put(gz, "fp", SECRET).ticket); pf.add("fp", "grandma")
gz.release(put(gz, "fp", SECRET).ticket)
fps = [x["detail"].split()[0] for x in audit_h.records if x["action"] == "AUDIENCE_RELEASING"]
ck("two different rosters leave two different audience fingerprints",
   len(fps) == 2 and fps[0] != fps[1])
plain = hashlib.sha256(SECRET_VALUE.encode()).hexdigest()
blob = " ".join(str(x) for x in audit_h.records + audit_g.records + audit_b.records)
ck("no record holds the value, the word 'planter', or a plain hash of the value",
   SECRET_VALUE not in blob and "planter" not in blob and plain not in blob)

print("\nI. REPLAY: the audience-rebind cases through the gate")
pf.make("family-chat", FAMILY); audit_i = _Audit(); gi = gate(pf, audit_i)
d = put(gi, "family-chat", SECRET); pf.add("family-chat", "george")
r = gi.release(d.ticket); again = put(gi, "family-chat", SECRET)
ck("C, live rebind: george joins after the hold, nothing reaches him",
   not r.sent and again.outcome is Outcome.HELD_FOR_HUMAN and pf.to("family-chat") == [])
pf.make("shared", FAMILY, history=True)
d = put(gi, "shared", SECRET); r = gi.release(d.ticket); pf.add("shared", "george")
ck("D, history visible: the original send is refused, so there is nothing to read later",
   r.outcome is Outcome.REFUSED_LABEL and pf.to("shared") == [])
pf.make("loop", FAMILY | {"george"})
# The session labels both drafts. An earlier version of this replay set
# SECRET_FAMILY on them by hand, so what held the paraphrase was the test author.
agent = gi.open_session("agent-loop", readable=[SECRET_FAMILY, INTERNAL])
t3 = gi.hold_clean_draft(gi.build_context("loop", BRIEF, [SECRET, SCHED]), "late")
clean_value = gi.review(t3.ticket)["value"]
t1 = gi.hold_agent_draft("loop", agent, "the key is under the blue flowerpot")
t2 = gi.hold_agent_draft("loop", agent, "look beneath the blue container beside the door")
ck("rewrite loop: the paraphrase is held exactly like the original; the clean draft goes",
   t1.outcome is t2.outcome is Outcome.HELD_FOR_HUMAN
   and gi.release(t3.ticket).outcome is Outcome.RELEASED
   and pf.to("loop") == [clean_value])

print("\nJ. The agent's own drafts: words from the agent, the label from its session")
pf.make("j-room", FAMILY | {"george"})
gj = gate(pf)
saw_household = gj.open_session("agent-1", readable=[SECRET_FAMILY, INTERNAL])
dj = gj.hold_agent_draft("j-room", saw_household,
                         "look beneath the blue container beside the door")
ck("a paraphrase from a session that could read the household is held for a human",
   dj.outcome is Outcome.HELD_FOR_HUMAN)
rj = gj.release(dj.ticket)
ck("and an automatic release refuses it; nothing reaches the room",
   rj.outcome is Outcome.REFUSED_LABEL and pf.to("j-room") == [])
cal_only = gj.open_session("agent-2", readable=[INTERNAL])
dj2 = gj.hold_agent_draft("j-room", cal_only, "pickup moved to 4pm Thursday")
ck("a session that could read only the calendar releases to the same room",
   dj2.outcome is Outcome.HELD and gj.release(dj2.ticket).outcome is Outcome.RELEASED)
gj.observe_for(cal_only, household.read())
dj3 = gj.hold_agent_draft("j-room", cal_only, "all good here")
ck("handing that session the household memory raises its label; its next draft is held",
   gj.session_label(cal_only) == SECRET_FAMILY
   and dj3.outcome is Outcome.HELD_FOR_HUMAN)
gj.observe_for(cal_only, HELLO)
ck("observing something PUBLIC afterwards does not lower it",
   gj.session_label(cal_only) == SECRET_FAMILY)
own = gj.hold_agent_draft("j-room", saw_household,
                          Labeled.public("the key is under the flowerpot"))
ck("a label arriving with the agent's words is refused, not used",
   own.outcome is Outcome.REFUSED_LABEL and own.ticket is None)
class _OwnSession:
    # Not the wall's session, but a convincing fake: it has everything a session
    # has and stamps its own words PUBLIC. If the gate stopped checking the type,
    # this would be held at PUBLIC rather than crash, so the check fails cleanly.
    session_id = "fake"
    label = PUBLIC
    def labelled(self, value):
        return Labeled.public(value)
fake = gj.hold_agent_draft("j-room", _OwnSession(), "the key is under the flowerpot")
ck("a stand-in session that labels its own words PUBLIC is refused",
   fake.outcome is Outcome.REFUSED_LABEL and fake.ticket is None)
try:
    AgentSession("agent-3", readable=[]); declared_nothing = "accepted"
except FlowRefused:
    declared_nothing = "refused"
except Exception as e:
    declared_nothing = f"crashed: {type(e).__name__}"
ck("a session that declares nothing readable is refused, not treated as PUBLIC",
   declared_nothing == "refused")

print("\nK. Error paths end in a decision that says what happened")
pf.make("k-room", FAMILY)
rk = gate(pf, _Audit(fail_on="AUDIENCE_REFUSED_SPENT")).release("no-such-ticket")
ck("a refusal whose record cannot be written still refuses, and says it was not recorded",
   rk.outcome is Outcome.REFUSED_SPENT and "could not be recorded" in rk.reason)
gk = gate(pf)
dk = put(gk, "k-room", HELLO)
pf.during_send = lambda: pf.down.add("k-room")
rk2 = gk.release(dk.ticket)
pf.during_send = None; pf.down.discard("k-room")
ck("a roster that cannot be read after the send counts as moved, not as clean",
   rk2.outcome is Outcome.RELEASED_ROSTER_MOVED)
gk3 = gate(pf, _Audit(fail_on="AUDIENCE_RELEASED"))
rk3 = gk3.release(put(gk3, "k-room", HELLO).ticket)
ck("a post-send record that fails is reported in the decision, not dropped",
   rk3.outcome is Outcome.RELEASED and "post-send record failed" in rk3.reason)

print("\nL. The v133 red team (Grok and Astra, 2026-09-11), one check per finding")
pf.make("l-room", FAMILY | {"george"})
g1_ctx = g.build_context("l-room", BRIEF, [HELLO])
ck("G1: a callable handed in at draft time is refused",
   refuses(lambda: g.hold_clean_draft(g1_ctx, lambda parts: SECRET_VALUE)))
poppy = AgentSession("poppy-1", readable=[PUBLIC]); poppy.observe(SECRET)
gp = gate(pf, drafters={"poppy": Drafter(lambda parts: SECRET_VALUE, poppy)})
dp = gp.hold_clean_draft(gp.build_context("l-room", BRIEF, [HELLO]), "poppy")
ck("G1: a registered drafter whose session saw the household drafts at its label: held",
   dp.outcome is Outcome.HELD_FOR_HUMAN
   and gp.release(dp.ticket).outcome is Outcome.REFUSED_LABEL and pf.to("l-room") == [])
pf.make("l-g1r", FAMILY | {"george"})
lying = gate(pf, drafters={"liar": Drafter(lambda parts: SECRET_VALUE,
                                           AgentSession("liar", readable=[PUBLIC]))})
dl = lying.hold_clean_draft(lying.build_context("l-g1r", BRIEF, [HELLO]), "liar")
ck("G1 RESIDUAL: a drafter registered as [PUBLIC] that has seen the secret still leaks it",
   lying.release(dl.ticket).sent and pf.to("l-g1r") == [SECRET_VALUE])

forged = DraftContext("l-room", BRIEF, (Labeled(SECRET_VALUE, PUBLIC),), g1_ctx.audience, 0)
ck("G2: a context this gate did not build is refused",
   refuses(lambda: g.hold_clean_draft(forged, "echo")))
edited = dataclasses.replace(g1_ctx, items=(Labeled(SECRET_VALUE, PUBLIC),))
ck("G2: a context from this gate with an item swapped after sealing is refused",
   refuses(lambda: g.hold_clean_draft(edited, "echo")))
ck("G2: there is no public hold() that takes a caller's Labeled", not hasattr(g, "hold"))

pf.make("l-g3", FAMILY, history=True)
g3 = gate(pf, declarations=[floor("l-g3", SECRET_FAMILY)])
first = g3.release(put(g3, "l-g3", SECRET).ticket)
pf.add("l-g3", "george")
nxt = put(g3, "l-g3", HELLO)
ck("G3 RESIDUAL: under a floor above PUBLIC, a later join is found at the next read, not prevented",
   first.sent and pf.to("l-g3") == [SECRET_VALUE]
   and nxt.outcome is Outcome.REFUSED_FLOOR_BREACH)

pf.make("l-g4", FAMILY | {"george"})
d4 = put(g, "l-g4", SECRET); pf.add("l-g4", "grandma"); rv4 = g.review(d4.ticket)
ck("G4: review of a draft whose room changed offers no action to sign",
   rv4["stale"] is True and rv4["action"] is None)
pf.make("l-l3", FAMILY | {"george"}, history=True)
rv3 = g.review(put(g, "l-l3", SECRET).ticket)
ck("L03: review shows history visibility, join floor, clearance and breach status",
   rv3["history_visible"] is True and rv3["join_floor"] == "PUBLIC"
   and rv3["clearance"] == "PUBLIC" and rv3["breached"] is False
   and rv3["cleared"] is False)

pf.make("l-g5", FAMILY, history=True)
def builds(**kw):
    try:
        gate(pf, **kw)
        return True
    except FlowRefused:
        return False
ck("G5: a floor above PUBLIC declared by an agent name, unattested, refuses the gate",
   not builds(declarations=[RoomDeclaration("l-g5", SECRET_FAMILY, "planner_agent_7")]))
ck("G5: an attestation for a different floor refuses the gate",
   not builds(declarations=[RoomDeclaration(
       "l-g5", SECRET_FAMILY, "parent_a",
       attestation=attest(join_floor_action(PLATFORM, "l-g5", INTERNAL)))]))
ck("G5: a floor attested by someone other than its declared author refuses the gate",
   not builds(declarations=[RoomDeclaration(
       "l-g5", SECRET_FAMILY, "parent_a",
       attestation=attest(join_floor_action(PLATFORM, "l-g5", SECRET_FAMILY),
                          GUEST_KEY, "guest"))]))
ck("G5: a PUBLIC floor needs no attestation, and an attested SECRET floor is accepted",
   builds(declarations=[RoomDeclaration("l-g5", PUBLIC, "anyone")])
   and builds(declarations=[floor("l-g5", SECRET_FAMILY)]))

pf.make("l-f1", FAMILY)
dn = put(gate(pf, _Audit(none_on="AUDIENCE_HELD")), "l-f1", HELLO)
ck("F01: a hold whose audit write returns no receipt does not happen",
   dn.outcome is Outcome.REFUSED_UNRECORDED and dn.ticket is None)
gn = gate(pf, _Audit(none_on="AUDIENCE_RELEASING"))
rn = gn.release(put(gn, "l-f1", HELLO).ticket)
ck("F01: a release whose audit write returns no receipt sends nothing",
   rn.outcome is Outcome.REFUSED_UNRECORDED and pf.to("l-f1") == [])

pf.make("l-f2", FAMILY, history=True); audit_f2 = _Audit()
gf2 = gate(pf, audit_f2, declarations=[floor("l-f2", SECRET_FAMILY)])
gf2.release(put(gf2, "l-f2", SECRET).ticket)
d_auto = put(gf2, "l-f2", HELLO); d_hum = put(gf2, "l-f2", SECRET)
act_hum = gf2.review(d_hum.ticket)["action"]
pf.add("l-f2", "stranger", bump=False)
r_auto = gf2.release(d_auto.ticket)
r_hum = gf2.release_by_human(d_hum.ticket, attest(act_hum), "approved before he joined")
breach = [x for x in audit_f2.records if x["action"] == "AUDIENCE_REFUSED_FLOOR_BREACH"]
ck("F02: a new member below the floor is a breach on both release paths, not staleness",
   r_auto.outcome is Outcome.REFUSED_FLOOR_BREACH
   and r_hum.outcome is Outcome.REFUSED_FLOOR_BREACH)
ck("F02: the breach record names the audience that was checked and the one found",
   len(breach) == 2 and all("checked=" in x["detail"] and "found=" in x["detail"]
                            for x in breach))

pf.make("l-f3", FAMILY | {"george"}); audit_f3 = _Audit(); g3b = gate(pf, audit_f3)
ck("F03: a non-text draft is refused, so '17' and 17 cannot share an approval",
   put(g3b, "l-f3", Labeled(17, SECRET_FAMILY)).outcome is Outcome.REFUSED_FORMAT)
s17 = g3b.open_session("agent-17", readable=[SECRET_FAMILY])
ta = g3b.hold_agent_draft("l-f3", s17, "17"); tb = g3b.hold_agent_draft("l-f3", s17, "17")
act_a = g3b.review(ta.ticket)["action"]
ck("F03: the same text in two tickets gets two actions; approving one does not release the other",
   act_a != g3b.review(tb.ticket)["action"]
   and g3b.release_by_human(tb.ticket, attest(act_a), "approved the other one").outcome
   is Outcome.REFUSED_HUMAN and pf.to("l-f3") == [])
held_digests = [x["detail"].split("digest=")[1][:64] for x in audit_f3.records
                if x["action"] == "AUDIENCE_HELD_FOR_HUMAN"]
ck("L02: equal texts leave different digests, so the log is no comparison oracle",
   len(held_digests) == 2 and held_digests[0] != held_digests[1])

pf.make("l-f4", FAMILY)
pf.source = "other-platform"
ck("F04: a roster from another platform is refused",
   put(g, "l-f4", HELLO).outcome is Outcome.REFUSED_ROSTER)
pf.source = PLATFORM
d4b = put(g, "l-f4", HELLO); pf.source = "other-platform"
r4b = g.release(d4b.ticket); pf.source = PLATFORM
ck("F04: a platform switch between hold and release sends nothing",
   r4b.outcome is Outcome.REFUSED_ROSTER and pf.to("l-f4") == [])

pf.make("l-f5", FAMILY); g5 = gate(pf)
for i in range(128):
    g5.release(put(g5, "l-f5", Labeled.public(f"{i:04d}" + "x" * 4092)).ticket)
ck("F05: 128 released drafts leave no ticket and no text behind",
   len(pf.to("l-f5")) == 128 and g5.pending() == 0 and len(g5._tickets) == 0)
gcap = gate(pf, max_held=3)
caps = [put(gcap, "l-f5", HELLO).outcome for _ in range(4)]
ck("F05: held drafts are capped in number",
   caps == [Outcome.HELD] * 3 + [Outcome.REFUSED_CAPACITY])
gsize = gate(pf, max_draft_chars=10)
ck("F05: a draft over the size cap is refused",
   put(gsize, "l-f5", Labeled.public("x" * 11)).outcome is Outcome.REFUSED_FORMAT)
gttl = gate(pf, max_hold_seconds=60)
dt = put(gttl, "l-f5", HELLO)
real_clock = ar._monotonic
ar._monotonic = lambda: real_clock() + 61
try:
    rt = gttl.release(dt.ticket); pend = gttl.pending()
finally:
    ar._monotonic = real_clock
ck("F05: a draft held past its lifetime expires with its text: refused, nothing pending",
   rt.outcome is Outcome.REFUSED_SPENT and pend == 0 and HELLO.value not in pf.to("l-f5"))
gnan = gate(pf); dnan = put(gnan, "l-f5", HELLO)
ar._monotonic = lambda: float("nan")
try:
    rnan = gnan.release(dnan.ticket); pend_nan = gnan.pending()
finally:
    ar._monotonic = real_clock
# NaN is false against < and against >, so an age test silently takes whichever
# branch it falls through to. That branch must not be the one that keeps a secret.
ck("F05: a clock that cannot say what time it is expires held drafts, it does not keep them",
   rnan.outcome is Outcome.REFUSED_SPENT and pend_nan == 0
   and not math.isfinite(float("nan")) and HELLO.value not in pf.to("l-f5"))

pf.make("l-l1", FAMILY); gl1 = gate(pf)
def blip(bump):
    def join_and_leave():
        pf.add("l-l1", "george", bump=bump); pf.leave("l-l1", "george", bump=bump)
    return join_and_leave
d = put(gl1, "l-l1", HELLO)
pf.during_send = blip(False); r_quiet = gl1.release(d.ticket); pf.during_send = None
ck("L01 RESIDUAL: a join and leave between the two reads, with no epoch change, is invisible",
   r_quiet.outcome is Outcome.RELEASED)
d = put(gl1, "l-l1", HELLO)
pf.during_send = blip(True); r_loud = gl1.release(d.ticket); pf.during_send = None
ck("L01: the same blip on a platform whose epoch advances is reported as a possible exposure",
   r_loud.outcome is Outcome.RELEASED_ROSTER_MOVED)

pf.make("l-l4", FAMILY)
gfalse = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=pf.roster,
                      send_fn=lambda room, value: False, audit=_Audit())
ck("L04: a sender that returns False is a failed send, not a delivery",
   gfalse.release(put(gfalse, "l-l4", HELLO).ticket).outcome is Outcome.SEND_FAILED)
async def _asend(room, value):
    pf.delivered.append((room, value))
try:
    AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=pf.roster,
                 send_fn=_asend, audit=_Audit())
    async_refused = False
except FlowRefused:
    async_refused = True
ck("L06: an async sender is refused when the gate is built", async_refused)
def _returns_coroutine(room, value):
    return _asend(room, value)
gco = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=pf.roster,
                   send_fn=_returns_coroutine, audit=_Audit())
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    rco = gco.release(put(gco, "l-l4", HELLO).ticket)
    gc.collect()
ck("L06: a sender that hands back a coroutine is a failed send, closed without a warning",
   rco.outcome is Outcome.SEND_FAILED and pf.to("l-l4") == []
   and not any("never awaited" in str(w.message) for w in caught))

pf.make("l-l7", FAMILY | {"george"})
g7 = gate(pf, disclosers=("parent_a", "guest"))
d7 = put(g7, "l-l7", SECRET)
r_guest = g7.release_by_human(d7.ticket, attest(g7.review(d7.ticket)["action"],
                                                GUEST_KEY, "guest"), "I say so")
ck("L07: a declared discloser not cleared for the label cannot release it",
   r_guest.outcome is Outcome.REFUSED_HUMAN and pf.to("l-l7") == [])
g7b = gate(pf, disclosers=())
d7b = put(g7b, "l-l7", SECRET)
r_nod = g7b.release_by_human(d7b.ticket, attest(g7b.review(d7b.ticket)["action"]),
                             "I am a parent")
ck("L07: a verified, cleared human who is not a declared discloser cannot release it",
   r_nod.outcome is Outcome.REFUSED_HUMAN and pf.to("l-l7") == [])



# ── v135: repairs to the Grok 2026-09-11 review of v134, plus two found here ──
print()
print("M. v136 repairs: the Grok v134 review, the Astra v135 review, and two found here")

_pf = Platform(); _pf.make("k-room", FAMILY | {"george"}, history=True)
_g = gate(_pf)

class _Liar(AgentSession):
    # Passes isinstance(). v134 accepted it and took PUBLIC from this property.
    @property
    def label(self): return PUBLIC

_d = _g.hold_agent_draft("k-room", _Liar("poppy-1", readable=[SECRET_FAMILY]), SECRET_VALUE)
ck("R1: an AgentSession subclass reporting PUBLIC is not a session id, and is refused",
   _d.outcome is Outcome.REFUSED_LABEL and _d.ticket is None and _pf.to("k-room") == [])

_h1 = _g.open_session("poppy-1", readable=[SECRET_FAMILY])
_d = _g.hold_agent_draft("k-room", _h1, SECRET_VALUE)
ck("R1: the same id, opened by the wall, holds at the label the wall gave it",
   _d.outcome is Outcome.HELD_FOR_HUMAN
   and _g.release(_d.ticket).outcome is Outcome.REFUSED_LABEL and _pf.to("k-room") == [])

ck("R2: reopening a live session id is refused rather than rebinding it lower",
   refuses_flow(lambda: _g.open_session("poppy-1", readable=[PUBLIC])))

_d = _g.hold_agent_draft("k-room", AgentSession("poppy-1", readable=[PUBLIC]), SECRET_VALUE)
ck("R2: a twin session built on a live id is an object, not an id, and is refused",
   _d.outcome is Outcome.REFUSED_LABEL and _pf.to("k-room") == [])

ck("R2: the refusal names the mechanism rather than the generic flow message",
   "session" in _d.reason and FlowRefused.GENERIC not in _d.reason)

for _ret, _want in ((None, False), (0, False), ("", False),
                    ("ERROR: not delivered", False), (1, False), (True, True)):
    _p = Platform(); _p.make("k-ack", {"parent_a"}, history=True)
    def _snd(room, value, _r=_ret):
        _p.delivered.append((room, value)); return _r
    _ga = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=_p.roster,
                       send_fn=_snd, audit=_Audit(), drafters=DRAFTERS,
                       disclosers=("parent_a",))
    _kh = _ga.open_session("k-a", readable=[PUBLIC])
    _h = _ga.hold_agent_draft("k-ack", _kh, "hello team")
    ck(f"R3: a sender returning {_ret!r} is "
       f"{'a delivery' if _want else 'a failed send'}",
       (_ga.release(_h.ticket).outcome is Outcome.RELEASED) is _want)

_one = Label(Level.SECRET, frozenset({"a,b"}))
_two = Label(Level.SECRET, frozenset({"a", "b"}))
ck("R11: two labels neither of which dominates the other print the same",
   str(_one) == str(_two) and not _one.dominates(_two) and not _two.dominates(_one))
ck("R11: label_token tells them apart, so their floor attestations differ",
   label_token(_one) != label_token(_two)
   and join_floor_action(PLATFORM, "k-room", _one)
       != join_floor_action(PLATFORM, "k-room", _two))

# history=False, so the PUBLIC join-floor cap cannot mask the race: on v134
# this room held the paraphrase at INTERNAL and released it.
_pf2 = Platform(); _pf2.make("k-race", FAMILY, history=False)
_g2 = gate(_pf2)
_sid = _g2.open_session("poppy-2", readable=[INTERNAL])
class _Racy:
    # The roster read is not instant. This hands the session the household memory
    # while that read is in flight, which is exactly the window v134 held through.
    def __init__(self, real): self.real, self.n = real, 0
    def __call__(self, room):
        self.n += 1
        if self.n == 1:
            _g2.observe_for(_sid, SECRET)
        return self.real(room)
_g2._roster_fn = _Racy(_pf2.roster)
_d = _g2.hold_agent_draft("k-race", _sid, "the key is under the blue flowerpot")
ck("NEW: a session handed a secret mid-hold voids the hold, it does not ride out "
   "under the label that was true before",
   _d.outcome is Outcome.REFUSED_LABEL and _d.ticket is None and _pf2.to("k-race") == [])

_pf3 = Platform(); _pf3.make("k-late", FAMILY | {"george"}, history=True)
_ds = AgentSession("k-drafter", readable=[PUBLIC])
def _reads_while_drafting(parts):
    _ds.observe(SECRET)          # the drafter reads the household while it drafts
    return "all fine here"
_g3 = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=_pf3.roster,
                   send_fn=_pf3.send, audit=_Audit(),
                   drafters={"late-reader": Drafter(_reads_while_drafting, _ds)},
                   disclosers=("parent_a",))
_d = _g3.hold_clean_draft(_g3.build_context("k-late", BRIEF, []), "late-reader")
ck("NEW: a drafter that reads a secret during its own call is covered; v134 read "
   "its label before the call and held the draft PUBLIC",
   _d.outcome is Outcome.HELD_FOR_HUMAN and _pf3.to("k-late") == [])


print()
print("N. v136: the Astra v135 review")

# F1 — knowing another session's id is not authority to write under it.
_pfa = Platform(); _pfa.make("n-room", FAMILY | {"george"}, history=False)
_ga1 = gate(_pfa)
_priv = _ga1.open_session("private-worker", readable=[SECRET_FAMILY])
_pub  = _ga1.open_session("public-worker",  readable=[PUBLIC])
_dp = _ga1.hold_agent_draft("n-room", _priv, SECRET_VALUE)
ck("F1: the session's own handle holds the secret for a human",
   _dp.outcome is Outcome.HELD_FOR_HUMAN
   and _ga1.release(_dp.ticket).outcome is Outcome.REFUSED_LABEL)
_ds = _ga1.hold_agent_draft("n-room", "public-worker", SECRET_VALUE)
ck("F1: naming another session by its id is refused; an id is not a handle",
   _ds.outcome is Outcome.REFUSED_LABEL and _ds.ticket is None and _pfa.to("n-room") == [])
ck("F1: the refusal does not say whether that id exists",
   "private-worker" not in _ds.reason and "public-worker" not in _ds.reason)
_dok = _ga1.hold_agent_draft("n-room", _pub, "public hello")
ck("F1: both sessions still work for their own holder",
   _dok.outcome is Outcome.HELD and _ga1.release(_dok.ticket).outcome is Outcome.RELEASED)

# F2 — what the gate shows a drafter, the drafter's session has seen.
_pfb = Platform()
_pfb.make("n-fam", FAMILY, history=False); _pfb.make("n-geo", FAMILY | {"george"}, history=False)
_keeps = []
def _remembers(parts):
    # Repeats a secret it was shown on an earlier call. On v135 this reached
    # george's room under PUBLIC, because the gate never recorded what it showed.
    _keeps.extend(parts)
    for _k in _keeps:
        if SECRET_VALUE in _k:
            return _k
    return "public hello"
_gb = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=_pfb.roster,
                   send_fn=_pfb.send, audit=_Audit(),
                   drafters={"keeper": Drafter(_remembers, AgentSession("keeper", readable=[PUBLIC]))},
                   disclosers=("parent_a",))
_gb.hold_clean_draft(_gb.build_context("n-fam", BRIEF, [SECRET]), "keeper")
_d2 = _gb.hold_clean_draft(_gb.build_context("n-geo", BRIEF, [HELLO]), "keeper")
ck("F2: a drafter that repeats a remembered secret is held at what it was shown, "
   "not at what it was registered as",
   _d2.outcome is Outcome.HELD_FOR_HUMAN
   and _gb._drafters["keeper"].session.label == SECRET_FAMILY
   and _gb.release(_d2.ticket).outcome is Outcome.REFUSED_LABEL
   and SECRET_VALUE not in [v for _, v in _pfb.delivered])

_pfc = Platform(); _pfc.make("n-fam", FAMILY, history=False); _pfc.make("n-geo", FAMILY | {"george"}, history=False)
_gc = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=_pfc.roster,
                   send_fn=_pfc.send, audit=_Audit(),
                   drafters={"fresh": Drafter(lambda parts: "all fine here",
                                              AgentSession("fresh", readable=[PUBLIC]),
                                              stateless=True, readable=(PUBLIC,))},
                   disclosers=("parent_a",))
_gc.hold_clean_draft(_gc.build_context("n-fam", BRIEF, [SECRET]), "fresh")
_d3 = _gc.hold_clean_draft(_gc.build_context("n-geo", BRIEF, [HELLO]), "fresh")
ck("F2: a stateless drafter gets a fresh session per call, so nothing carries",
   _d3.outcome is Outcome.HELD and _gc.release(_d3.ticket).outcome is Outcome.RELEASED)
ck("F2: declaring stateless without the labels its session starts from is refused",
   refuses(lambda: Drafter(lambda parts: "x", AgentSession("s", readable=[PUBLIC]),
                           stateless=True)))

# F3 — swapping a label for an incomparable one breaks the context seal.
_AB1, _AB2 = Label(Level.SECRET, frozenset({"a,b"})), Label(Level.SECRET, frozenset({"a", "b"}))
_pfd = Platform(); _pfd.make("n-seal", {"parent_a"}, history=False)
_gd = AudienceGate(platform=PLATFORM, clearances={"parent_a": _AB1},
                   roster_fn=_pfd.roster, send_fn=_pfd.send, audit=_Audit(),
                   drafters=DRAFTERS, disclosers=("parent_a",))
_ctx = _gd.build_context("n-seal", BRIEF, [Labeled("synthetic", _AB1)])
_swapped = dataclasses.replace(_ctx, items=(Labeled("synthetic", _AB2),))
ck("F3: the two labels still print the same and neither dominates the other",
   str(_AB1) == str(_AB2) and not _AB1.dominates(_AB2) and not _AB2.dominates(_AB1))
ck("F3: the context really does carry the item, so the swap is a label swap and "
   "not a shorter list",
   len(_ctx.items) == 1 and _ctx.withheld == 0)
ck("F3: swapping one for the other is refused; the seal names the label it sealed",
   refuses(lambda: _gd.hold_clean_draft(_swapped, "echo")))

# F4 — an audit that hands back a coroutine wrote nothing.
class _AsyncAudit:
    def __init__(self): self.records = []
    async def record(self, **kw):
        self.records.append(kw); return "receipt"
ck("F4: a gate whose audit record() is async refuses to be built",
   refuses_flow(lambda: AudienceGate(
       platform=PLATFORM, clearances=CLEAR, roster_fn=Platform().roster,
       send_fn=lambda r, v: True, audit=_AsyncAudit(), drafters=DRAFTERS,
       disclosers=("parent_a",))))

class _SneakyAudit:
    # Synchronous signature, coroutine return: the shape the build check misses.
    def __init__(self): self.records = []
    def record(self, **kw):
        async def _w(): self.records.append(kw)
        return _w()
_pfe = Platform(); _pfe.make("n-async", {"parent_a"}, history=False)
_ae = _SneakyAudit()
_ge = AudienceGate(platform=PLATFORM, clearances=CLEAR, roster_fn=_pfe.roster,
                   send_fn=_pfe.send, audit=_ae, drafters=DRAFTERS, disclosers=("parent_a",))
_he = _ge.open_session("n-a", readable=[PUBLIC])
_de = _ge.hold_agent_draft("n-async", _he, "hello team")
ck("F4: a coroutine receipt is not a receipt; nothing is held and nothing sent",
   _de.outcome is Outcome.REFUSED_UNRECORDED and _de.ticket is None
   and _ae.records == [] and _pfe.to("n-async") == [])

# F5 — every label a reviewer is shown is unambiguous.
_pff = Platform(); _pff.make("n-rev", {"parent_a"}, history=False)
_gf = AudienceGate(platform=PLATFORM, clearances={"parent_a": _AB1},
                   roster_fn=_pff.roster, send_fn=_pff.send, audit=_Audit(),
                   drafters=DRAFTERS, disclosers=("parent_a",))
_rev = _gf.review(put(_gf, "n-rev", HELLO).ticket)
ck("F5: review carries an id and a structured form for label, clearance and floor",
   {"label_id", "clearance_id", "join_floor_id",
    "label_parts", "clearance_parts", "join_floor_parts"} <= set(_rev))
ck("F5: two incomparable clearances give a reviewer different clearance ids",
   label_token(_AB1) != label_token(_AB2)
   and _label_parts(_AB1)["compartments"] != _label_parts(_AB2)["compartments"])

print("\n" + "=" * 56)
print(f"{sum(P)}/{EXPECTED_CHECKS} checks passed")
if len(P) != EXPECTED_CHECKS or not all(P):
    raise SystemExit(1)
