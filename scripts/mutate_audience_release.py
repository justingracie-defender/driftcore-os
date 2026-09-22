# SPDX-License-Identifier: Apache-2.0
"""
mutate_audience_release.py - does each mechanism in audience_release.py have a
check that goes red when it is removed?

Copies the repository to a temporary directory and, one at a time, replaces an
exact anchor in the copy's audience_release.py, then runs test_audience_release.py
there. A mutation counts as KILLED only if the run exits nonzero AND every check it
names is red. A mutation whose anchor does not match exactly once is reported as
DID NOT APPLY and fails the run: a mutation that silently misses reports a false
pass, and this repository has been caught by that more than once.

Some protections are held by more than one mechanism on purpose. For those, each
single mutation is EXPECTED to survive, and the combination must kill; both halves
are checked, so the redundancy is a measured fact rather than a hope.

STALE BYTECODE, found by this runner reporting a survivor that was not one
(2026-09-11). CPython invalidates a cached .pyc by the source's mtime IN WHOLE
SECONDS and its size in bytes. Two mutations of the same file written in the same
second with the same byte length are indistinguishable to that check, so the second
one imports the FIRST one's bytecode and the test never sees it. Eight pairs in the
list below collide on length; M9b and M10 collide and run back to back, so M10 ran
M9b's module and was reported SURVIVED on M9b's red check. The interpreter was
answering a question about code it had not loaded, which is the same class of thing
as a guard that returns ALLOW when it cannot evaluate: AN UNVERIFIED STATE WAS
CONVERTED INTO A RESULT. Bytecode writing is off in the subprocesses and any cache
is removed before each run, and the runner now checks that the source on disk at
launch is the mutated one.

Run: python3 scripts/mutate_audience_release.py     (exit 0 only if all as expected)
"""
import os, pathlib, re, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = tempfile.mkdtemp(prefix="mutate_audience_release_")
shutil.copytree(ROOT, BASE, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", ".git"))
MOD = f"{BASE}/driftcore/governance/audience_release.py"
ORIG = open(MOD).read()

# (name, claim, anchor, replacement, checks that must go red)
M = [
 ("M1 label check at release off", "release-follows-the-current-room",
  '        if not clearance.dominates(t.label):\n            self._settle(t, "held")\n            return self._refuse(Outcome.REFUSED_LABEL',
  '        if False:\n            self._settle(t, "held")\n            return self._refuse(Outcome.REFUSED_LABEL',
  ["george in the room"]),
 ("M2 members dropped from fingerprint", "release-follows-the-current-room",
  '"1" if r.history_visible else "0",\n                 *sorted(r.members)):',
  '"1" if r.history_visible else "0"):',
  ["WITHOUT an epoch change"]),
 ("M3 stale check off", "stale-roster-refuses",
  '        if fp != t.audience:\n            self._settle(t, "void")',
  '        if False:\n            self._settle(t, "void")',
  ["FULLY cleared one", "changed after the human signed"]),
 ("M4 history floor not applied", "future-members-count-where-history-shows",
  '        if r.history_visible:\n            clearance = meet_all([clearance, floor])',
  '        if False:\n            clearance = meet_all([clearance, floor])',
  ["history-visible room, no declaration", "D, history visible"]),
 ("M5 unregistered members skipped", "unregistered-member-is-public",
  'cleared = [self._clearances.get(m, PUBLIC) for m in r.members]',
  'cleared = [self._clearances[m] for m in r.members if m in self._clearances]',
  ["unregistered member counts as PUBLIC"]),
 ("M6 wrong-room answer accepted", "unreadable-roster-refuses",
  '        if r.room != room:\n',
  '        if False:\n',
  ["different room"]),
 ("M6b unreadable at release voids the ticket", "unreadable-roster-refuses",
  '        except RosterUnreadable as e:\n            self._settle(t, "held")\n            return self._refuse(Outcome.REFUSED_ROSTER, ticket, t.room, "",',
  '        except RosterUnreadable as e:\n            self._settle(t, "void")\n            return self._refuse(Outcome.REFUSED_ROSTER, ticket, t.room, "",',
  ["unreadable at release"]),
 ("M7 clean draft held at PUBLIC", "draft-label-is-assigned-by-the-wall",
  '        return self._hold(context.room, out, label, frozenset(origins))',
  '        return self._hold(context.room, out, PUBLIC, frozenset(origins))',
  ["wall labels the draft"]),
 ("M7b drafter may label itself", "draft-label-is-assigned-by-the-wall",
  '        if isinstance(out, Labeled):\n            raise BuildRefused("the drafter returned its own label; the wall assigns it")',
  '        if False:\n            raise BuildRefused("the drafter returned its own label; the wall assigns it")',
  ["handing back its own label"]),
 ("M8 context builder keeps everything", "drafter-sees-only-what-the-room-may-hold",
  '            if clearance.dominates(c.label):\n                if type(c.value) is not str:',
  '            if True:\n                if type(c.value) is not str:',
  ["holds only what the room may hold", "cannot echo the secret", "rewrite loop"]),
 ("M9 brief not checked", "tainted-brief-refuses",
  '        if not clearance.dominates(brief.label):\n',
  '        if False:\n',
  ["refuses the whole build"]),
 ("M9b bare candidates tolerated", "drafter-sees-only-what-the-room-may-hold",
  '            if not isinstance(c, Labeled):\n                raise BuildRefused(',
  '            if False:\n                raise BuildRefused(',
  ["bare candidate refuses the build"]),
 ("M10 a ticket being sent can be reserved again", "exact-bytes-once",
  '            if t is None or t.state != "held":\n                return None\n            t.state = "releasing"',
  '            if t is None:\n                return None\n            t.state = "releasing"',
  ["while the same ticket is being sent"]),
 ("M10b different bytes sent", "exact-bytes-once",
  '            result = self._send_fn(t.room, t.value)',
  '            result = self._send_fn(t.room, t.value + " ")',
  ["exactly what was held"]),
 ("M11 attestation checked against itself", "human-release-binds-the-audience",
  'if not is_human(attestation, action=action, attestation_required=True):',
  'if not is_human(attestation, action=getattr(attestation, "action", None), attestation_required=True):',
  ["different draft releases nothing"]),
 ("M12 floor breach not checked at hold", "floor-breach-is-not-a-routine-refusal",
  '        if breached:\n            return self._refuse(Outcome.REFUSED_FLOOR_BREACH, None, room, fp,',
  '        if False:\n            return self._refuse(Outcome.REFUSED_FLOOR_BREACH, None, room, fp,',
  ["below the declared floor", "recorded under its own name"]),
 ("M13 no post-send roster check", "post-send-change-is-recorded",
  '        return after != fp',
  '        return False',
  ["join during delivery"]),
 ("M14 hold proceeds unrecorded", "unrecorded-release-refuses",
  '                except _Unrecorded as e:\n                    return Decision(Outcome.REFUSED_UNRECORDED, None, room, fp,\n                                    f"audit write failed ({e}); nothing held")',
  '                except _Unrecorded as e:\n                    pass',
  ["hold record cannot be written", "F01: a hold whose audit write returns no receipt"]),
 ("M14b release proceeds unrecorded", "unrecorded-release-refuses",
  '        except _Unrecorded as e:\n            self._settle(t, "held")\n            return Decision(Outcome.REFUSED_UNRECORDED, ticket, t.room, fp,\n                            f"audit write failed ({e}); nothing sent")',
  '        except _Unrecorded as e:\n            pass',
  ["release record cannot be written", "F01: a release whose audit write returns no receipt"]),
 ("M15 audience fingerprint left out of records", "audit-names-the-audience-not-the-content",
  'detail = (f"audience={fp} room={room} members={n} label={label} "',
  'detail = (f"audience=- room={room} members={n} label={label} "',
  ["two different audience fingerprints"]),
 ("M15b unkeyed digest", "audit-names-the-audience-not-the-content",
  '        return hmac.new(self._digest_key,\n                        ticket.encode("ascii") + b"\\x00" + text.encode("utf-8"),\n                        hashlib.sha256).hexdigest()',
  '        return hashlib.sha256(text.encode("utf-8")).hexdigest()',
  ["plain hash of the value", "L02"]),
 ("MA1 agent draft held at PUBLIC", "agent-draft-carries-session-label",
  '        return self._hold(room, text, label,\n                          frozenset({f"agent:{session.session_id}"}),',
  '        return self._hold(room, text, PUBLIC,\n                          frozenset({f"agent:{session.session_id}"}),',
  ["paraphrase from a session that could read", "rewrite loop"]),
 ("MA2 observe does not raise the label", "agent-draft-carries-session-label",
  '            self._label = self._label.join(item.label)',
  '            self._label = self._label',
  ["raises its label"]),
 ("MA3 observe replaces instead of joining", "agent-draft-carries-session-label",
  '            self._label = self._label.join(item.label)',
  '            self._label = item.label',
  ["does not lower it"]),
 ("MA4 a label arriving with the words is used", "agent-draft-carries-session-label",
  '        if isinstance(text, Labeled):\n            return self._refuse(Outcome.REFUSED_LABEL, None, room, "",\n                                "the agent supplies words, not a label")',
  '        if isinstance(text, Labeled):\n            return self._hold(room, text.value, text.label, text.origins)',
  ["label arriving with the agent"]),
 ("MA5 declaring nothing reads as PUBLIC", "agent-draft-carries-session-label",
  '        if not labels:\n            raise FlowRefused(',
  '        if False:\n            raise FlowRefused(',
  ["declares nothing readable"]),
 ("MA6 any object or another session's id accepted", "the-wall-owns-the-session",
  '        with self._lock:\n            s = self._sessions.get(handle)\n        if s is None:',
  '        with self._lock:\n            s = (self._sessions.get(handle)\n                 or next((v for v in self._sessions.values()\n                          if v.session_id == handle), None))\n        if s is None:',
  ["F1: naming another session by its id"]),
 ("MB1 refusal record failure dropped", "(error path)",
  '            return Decision(outcome, ticket, room, fp,\n                            f"{why}; this refusal could not be recorded ({type(e).__name__})")',
  '            return Decision(outcome, ticket, room, fp, why)',
  ["still refuses, and says it was not recorded"]),
 ("MB2 unreadable roster after send = unmoved", "post-send-change-is-recorded",
  '        except RosterUnreadable:\n            return True',
  '        except RosterUnreadable:\n            return False',
  ["cannot be read after the send"]),
 ("MB3 post-send record failure dropped", "(error path)",
  '            return Decision(outcome, ticket, t.room, fp,\n                            f"{why}; the post-send record failed ({e})")',
  '            return Decision(outcome, ticket, t.room, fp, why)',
  ["post-send record that fails"]),
 # v134, one or more per repaired finding.
 ("N1 G1 callable accepted at draft time", "drafter-is-registered",
  '        reg = self._drafters.get(drafter) if isinstance(drafter, str) else None',
  '        reg = (self._drafters.get(drafter) if isinstance(drafter, str)\n               else Drafter(drafter, AgentSession("adhoc", [PUBLIC])))',
  ["G1: a callable handed in at draft time"]),
 ("N2 G1 drafter's own session not joined", "draft-label-is-assigned-by-the-wall",
  '        label = session.label\n',
  '        label = PUBLIC\n',
  ["G1: a registered drafter whose session saw the household"]),
 ("N3 G2 seal not checked", "one-minting-path",
  '        if not hmac.compare_digest(context.seal.encode("utf-8"), expected.encode("ascii")):\n            raise BuildRefused(',
  '        if False:\n            raise BuildRefused(',
  ["G2: a context this gate did not build", "G2: a context from this gate with an item swapped"]),
 ("N26 G2 a public hold() re-added", "one-minting-path",
  '    def review(self, ticket: str) -> dict:',
  '    def hold(self, room, draft):\n        return self._hold(room, draft.value, draft.label, draft.origins)\n\n    def review(self, ticket: str) -> dict:',
  ["G2: there is no public hold()"]),
 ("N4 F01 no receipt accepted", "unrecorded-release-refuses",
  '        if not receipt:\n            # driftcore.audit.record() reports',
  '        if False:\n            # driftcore.audit.record() reports',
  ["F01: a hold whose audit write returns no receipt", "F01: a release whose audit write returns no receipt"]),
 ("N5 F02 staleness checked before the breach", "floor-breach-is-not-a-routine-refusal",
  '            return self._refuse(Outcome.REFUSED_ROSTER, ticket, t.room, "",\n                                e.operator_detail)\n        if breached:',
  '            return self._refuse(Outcome.REFUSED_ROSTER, ticket, t.room, "",\n                                e.operator_detail)\n        if fp != t.audience:\n            self._settle(t, "void")\n            return self._refuse(Outcome.REFUSED_STALE, ticket, t.room, fp, "stale")\n        if breached:',
  ["F02: a new member below the floor is a breach on both release paths"]),
 ("N6 F02 breach record without the two audiences", "floor-breach-is-not-a-routine-refusal",
  'f"checked={t.audience} found={fp}; what was released "',
  'f"what was released "',
  ["F02: the breach record names the audience"]),
 ("N7 F03 non-text coerced to text", "text-committed-per-ticket",
  '        problem = self._text_problem(value)\n',
  '        value = value if type(value) is str else str(value)\n        problem = self._text_problem(value)\n',
  ["F03: a non-text draft is refused"]),
 ("N9 L02 digest without the ticket", "text-committed-per-ticket",
  '                        ticket.encode("ascii") + b"\\x00" + text.encode("utf-8"),',
  '                        text.encode("utf-8"),',
  ["L02: equal texts leave different digests"]),
 ("N10 F04 platform not pinned", "unreadable-roster-refuses",
  '        if r.source != self._platform:\n            raise RosterUnreadable(',
  '        if False:\n            raise RosterUnreadable(',
  ["F04: a roster from another platform is refused", "F04: a platform switch between hold and release"]),
 ("N11 F05 spent tickets kept with their text", "spent-drafts-are-disposed",
  '                self._tickets.pop(t.tid, None)\n                t.value = ""',
  '                pass',
  ["F05: 128 released drafts leave no ticket"]),
 ("N12 F05 no cap on held drafts", "spent-drafts-are-disposed",
  '            if len(self._tickets) >= self._max_held:',
  '            if False:',
  ["F05: held drafts are capped in number"]),
 ("N13 F05 held drafts never expire", "spent-drafts-are-disposed",
  '        return 0 <= now - held_at <= cap',
  '        return True',
  ["F05: a draft held past its lifetime expires"]),
 ("N14 F05 no size cap", "text-committed-per-ticket",
  '        if len(value) > self._max_chars:\n',
  '        if False:\n',
  ["F05: a draft over the size cap"]),
 ("N15 G4 review offers a dead action", "review-shows-exposure",
  '                "action": None if (stale or breached)\n                else _human_action(ticket, room, digest, fp)}',
  '                "action": _human_action(ticket, room, digest, fp)}',
  ["G4: review of a draft whose room changed offers no action"]),
 ("N16 L03 review hides the exposure facts", "review-shows-exposure",
  '"history_visible": r.history_visible, "join_floor": str(floor),',
  '"history_visible": None, "join_floor": None,',
  ["L03: review shows"]),
 ("N17 G5 floors above PUBLIC unverified", "join-floor-needs-a-human",
  '            if not PUBLIC.dominates(d.join_floor):\n                self._verify_floor(d)',
  '            if False:\n                self._verify_floor(d)',
  ["G5: a floor above PUBLIC declared by an agent name", "G5: an attestation for a different floor",
   "G5: a floor attested by someone other"]),
 ("N18 G5 floor author not bound", "join-floor-needs-a-human",
  '        if getattr(att, "principal", None) != d.declared_by:\n            raise FlowRefused(',
  '        if False:\n            raise FlowRefused(',
  ["G5: a floor attested by someone other than its declared author"]),
 ("N19 G5 floor attestation not bound to the floor", "join-floor-needs-a-human",
  '        action = join_floor_action(self._platform, d.room, d.join_floor)',
  '        action = getattr(att, "action", None)',
  ["G5: an attestation for a different floor"]),
 ("N21 L07 discloser's clearance ignored", "disclosure-needs-authority",
  '                or not self._clearances.get(principal, PUBLIC).dominates(t.label)):',
  '                or False):',
  ["L07: a declared discloser not cleared for the label"]),
 ("N22 L04 anything not False counts as sent", "sender-must-accept",
  '        if result is not True:',
  '        if result is False:',
  ["R3: a sender returning None", "R3: a sender returning ''",
   "R3: a sender returning 0", "R3: a sender returning 1"]),
 ("N23 L06 async sender accepted", "sender-must-accept",
  '        if _is_async(send_fn):\n            raise FlowRefused(',
  '        if False:\n            raise FlowRefused(',
  ["L06: an async sender is refused"]),
 ("N24 L06 an awaitable counts as sent", "sender-must-accept",
  '        if inspect.isawaitable(result):\n            if inspect.iscoroutine(result):\n                result.close()\n            return self._refuse(',
  '        if False:\n            if inspect.iscoroutine(result):\n                result.close()\n            return self._refuse(',
  ["L06: a sender that hands back a coroutine"]),
 ("N25 L01 epoch left out of the fingerprint", "post-send-change-is-recorded",
  '    for part in (r.source, r.room, str(r.epoch), "1" if r.history_visible else "0",',
  '    for part in (r.source, r.room, "1" if r.history_visible else "0",',
  ["L01: the same blip on a platform whose epoch advances"]),
]

# Held by more than one mechanism on purpose. Each part alone must SURVIVE (the
# other mechanism still holds) and all of them together must kill.
PARTS = {
 "M11b attestation not required": (
  'if not is_human(attestation, action=action, attestation_required=True):',
  'if not is_human(attestation, action=action, attestation_required=False):'),
 "N20 discloser list ignored": (
  '        if (principal not in self._disclosers\n',
  '        if (False\n'),
 "N21 discloser clearance ignored": (
  '                or not self._clearances.get(principal, PUBLIC).dominates(t.label)):',
  '                or False):'),
 "N8 ticket left out of the action": (
  '    return f"audience_release:{ticket}:{room}:{digest}:{audience}"',
  '    return f"audience_release:{room}:{digest}:{audience}"'),
 "N9 digest without the ticket": (
  '                        ticket.encode("ascii") + b"\\x00" + text.encode("utf-8"),',
  '                        text.encode("utf-8"),'),
 "M3 stale check off": (
  '        if fp != t.audience:\n            self._settle(t, "void")',
  '        if False:\n            self._settle(t, "void")'),
 "N13b the isfinite check removed": (
  '        if not math.isfinite(now) or not math.isfinite(held_at) or not math.isfinite(cap):\n            return False',
  '        if False:\n            return False'),
 "N13c the age test written in rejecting polarity": (
  '        return 0 <= now - held_at <= cap',
  '        return not (now - held_at > cap)'),
 "M1 label check at release off": (
  '        if not clearance.dominates(t.label):\n            self._settle(t, "held")\n            return self._refuse(Outcome.REFUSED_LABEL',
  '        if False:\n            self._settle(t, "held")\n            return self._refuse(Outcome.REFUSED_LABEL'),
}
MULTI = [
 ("bare name: attestation + disclosers + clearance", "human-release-binds-the-audience",
  ["M11b attestation not required", "N20 discloser list ignored", "N21 discloser clearance ignored"],
  ["label-only process, a bare name"]),
 ("same text, two tickets: action + digest", "text-committed-per-ticket",
  ["N8 ticket left out of the action", "N9 digest without the ticket"],
  ["F03: the same text in two tickets gets two actions"]),
 ("non-finite clock: isfinite + comparison polarity", "spent-drafts-are-disposed",
  ["N13b the isfinite check removed", "N13c the age test written in rejecting polarity"],
  ["F05: a clock that cannot say what time it is"]),
 ("replay C: stale + label", "release-follows-the-current-room",
  ["M3 stale check off", "M1 label check at release off"],
  ["C, live rebind"]),
]


ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}


def run(src):
    open(MOD, "w").write(src)
    for cache in pathlib.Path(BASE).rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    if open(MOD).read() != src:
        raise SystemExit("the mutated source is not what is on disk; refusing to report")
    try:
        p = subprocess.run([sys.executable, "test_audience_release.py"], cwd=BASE,
                           capture_output=True, text=True, timeout=300, env=ENV)
    finally:
        open(MOD, "w").write(ORIG)
    out = p.stdout
    fails = [l.split("] ", 1)[1] for l in out.splitlines() if "[FAIL]" in l]
    crashed = not re.search(r"\d+/\d+ checks passed", out)
    return p.returncode, fails, crashed


def apply(src, anchor, repl):
    if src.count(anchor) != 1:
        return None
    return src.replace(anchor, repl)


ok = True
print(f"{'mutation':50s} {'exit':>4}  result")
for name, claim, anchor, repl, expect in M:
    src = apply(ORIG, anchor, repl)
    if src is None:
        print(f"{name:50s}  DID NOT APPLY (anchor count {ORIG.count(anchor)})"); ok = False; continue
    rc, fails, crashed = run(src)
    hit = [e for e in expect if any(e in f for f in fails)]
    killed = rc != 0 and len(hit) == len(expect)
    ok &= killed
    print(f"{name:50s} {rc:>4}  {'KILLED' if killed else 'SURVIVED'} - {len(fails)} red"
          + (" then CRASHED" if crashed else ""))

for label, claim, names, expect in MULTI:
    for n in names:
        a, r = PARTS[n]
        src = apply(ORIG, a, r)
        if src is None:
            print(f"  {n:48s}  DID NOT APPLY"); ok = False; continue
        rc, fails, crashed = run(src)
        alone_red = any(e in f for e in expect for f in fails)
        ok &= not alone_red
        print(f"  {n:48s} {rc:>4}  {'SURVIVES ALONE, as expected' if not alone_red else 'KILLED ALONE: not redundant after all'}")
    src = ORIG
    for n in names:
        a, r = PARTS[n]
        src = apply(src, a, r)
        if src is None:
            break
    if src is None:
        print(f"{label:50s}  DID NOT APPLY (combined)"); ok = False; continue
    rc, fails, crashed = run(src)
    killed = rc != 0 and all(any(e in f for f in fails) for e in expect)
    ok &= killed
    print(f"{label:50s} {rc:>4}  {'KILLED' if killed else 'SURVIVED'} (all parts together)")

shutil.rmtree(BASE, ignore_errors=True)
print("\nALL MUTATIONS AS EXPECTED" if ok else "\nSOME MUTATIONS SURVIVED, KILLED ALONE, OR DID NOT APPLY")
sys.exit(0 if ok else 1)
