# Two-Ended Drift: Keeping Judgment Anchored Where It Belongs

*On why protecting the human from drift is the same project as protecting
the machine from it — and why "oversight" can be alive on paper and dead
in practice.*

---

> *The safest system is the one that knows what it knows — and says so.*
> The companion to that line: the safest system is also one whose humans
> still know what **they** know — and are still the ones deciding.

---

## The Short Version

DriftCore began by watching the **machine** slide off its grounding:
sycophancy, value drift, confident falsehood, the slow bending of a
system away from the principles it was given. The two-lane drift detector,
the consistency probe, the "say I don't know" rule — all of it points at
one thing: *the AI's behavior drifting from its values.*

The anti-reverse-centaur work points at the mirror image: the **human**
sliding off **theirs** — anchoring on the machine's answer, deskilling
into a reflex, getting worn down into a rubber-stamp.

These look like two different problems. They are not. They are the same
problem from two ends: **judgment slipping away from where it is supposed
to live.** In one case the AI's behavior drifts from its values. In the
other the human's authority drifts to the machine. The constant DriftCore
defends — the thing under both — is this:

> **Keep judgment anchored where it belongs.**

---

## The Two Ends

**End one — the machine drifts from its values.** A trained system has no
written rule to point to; its values are smeared across a tangle of
weights (see `WHY_LEGIBILITY.md`). Left alone, it can drift toward
whatever is rewarded — telling people what they want to hear, sounding
certain past its evidence, quietly optimizing for approval. DriftCore
answers this structurally: explicit invariants, drift detection, an
audit chain that cannot be edited, a verdict layer that refuses to let
the system grade its own homework (`reflection.py`).

**End two — the human's authority drifts to the machine.** Put the AI's
answer in front of a person before they form their own, and the person
stops reading and starts deferring. This is not a character flaw; it is
measured and reliable. In one mammography study, when a system showed
radiologists a wrong AI suggestion, accuracy among readers with fifteen
years of experience fell from 82% to below 46%. The skill did not
vanish — it was bypassed. Do that daily for a year and the independent
read atrophies into a click. The human is still "in the loop," and the
loop means nothing.

The proposed `second_reader` gate answers end two with the same shape of
move DriftCore already uses for end one: make the right thing structural,
not hoped-for. The human reads and **commits** before the machine is
revealed (you cannot be anchored by an answer you have not seen). The AI
flag can **raise** scrutiny but never **lower** it (it opens a question,
never closes one). And the workload floor is governance the AI cannot
touch (the tool's existence cannot be used to work the human harder).

---

## The Failure Mode That Hides: Enabled but Meaningless

The constitution's second invariant is **HUMAN_OVERSIGHT_CANNOT_BE_DISABLED.**
At the code level you can prove it: the off-switch is wired, the pause
works, no agent can remove them. But there is a failure mode the code
cannot see.

**You can leave oversight perfectly enabled and still make it meaningless.**

The radiologist still clicks OK. The checkbox is right there, alive,
auditable. But the independent judgment behind the click has been worn
down to a reflex — so the oversight is alive on paper and dead in
practice. Control is not only lost by the machine seizing it. It is also
lost by the human quietly letting go.

This has a non-AI twin worth naming plainly. Amazon never disabled anyone's
bathroom access. They simply built a system whose pace made using it
impossible, then logged the consequences as the worker's infraction. The
right was enabled. The right was meaningless. Same move.

So protecting the human from drift is **not a bonus feature bolted onto
DriftCore.** It is a precondition for the founding sentence —
*the people a system serves must remain in control of it* — to mean
anything at all. Oversight that has been hollowed out is not oversight.
A floor under the human's judgment is what keeps the invariant honest.

---

## The Honest Limit

DriftCore cannot make a human sharp. People drift on their own — we get
tired, we defer, we coast — and no architecture fixes that. The claim
here is narrower, and it is the same shape as every other claim in this
project: DriftCore can refuse to **build the drift in.** It can decline
to construct the workflow that manufactures human deskilling the way a
throughput algorithm manufactures the pee bottle. It cannot keep a person
whole; it can decline to dull them on purpose.

The opposite of the reverse-centaur is not a sharper human. It is a
system that was never arranged to use one up.

---

## Where This Lives in the Code

| End of the drift | What defends it |
|------------------|-----------------|
| Machine drifts from its values | `drift/` two-lane detector, `probe/` consistency, `verification/reflection.py` (no self-grading), the immutable invariants |
| Human's authority drifts to the machine | `verification/second_reader.py` *(proposed)* — commit-before-reveal, AI raises-but-never-lowers, a workload floor the AI cannot lower |
| The shared precondition | Constitution §2 **HUMAN_OVERSIGHT_CANNOT_BE_DISABLED** — read here as *oversight that still means something*, not just oversight that still exists |

---

*Note: `second_reader.py` is PROPOSED — built and tested in isolation,
not yet wired into the coordinator. This document is the reasoning it
answers to; if the code and this disagree, that disagreement is a bug to
investigate, not a fact to accept.*

*For the future. For the kids.*
