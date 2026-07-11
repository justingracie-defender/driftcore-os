# Psychological Safety Guard — Design Doc

**Status:** DESIGN (not code). Companion to `SPEECH_LAYER_CONTENT_GOVERNANCE.md`,
`SPEECH_LAYER_OUTPUT_BACKSTOP.md`, and `THREAT_BOUNDARIES.md`.
**Scope:** the speech-layer control for **relational and psychological influence** —
the category of harm where a reply is grammatically polite yet materially increases a
vulnerable person's risk (validating hopelessness, fostering dependence on the AI,
discouraging real-world support). Speech as action, applied to the person's *decisions*.

> ## ★ NORTH STAR (read before anything else)
> **The single most important thing this module does is get a hurting person to a
> HUMAN faster — not be a better AI companion to them.** If this layer ever makes the
> AI *stickier* for someone in crisis, it has FAILED, no matter how empathetic the
> replies are. The core alleged failure in the cases that motivate this design is an
> AI that kept a suicidal person talking to *it* instead of routing them to *people*.
> So the primary output of this module is the **Seek-Human shift**; everything else is
> secondary. This sentence is at the top on purpose.

---

## 0. The honest architecture: interlock vs. backstop (the whole design)

The tempting framing — "a Psychological Safety Guard that vetoes unsafe replies like a
hardware interlock" — is **half right and half dangerous**, and getting the split
right is the entire contribution of this document.

**A physical invariant (never exceed 60 N) is enforced by PHYSICS. A judgment about
whether a reply 'reinforces despair' is made by a MODEL — and models read surface,**
so that judgment carries the same evasion and distribution-shift limits as every other
classifier (see the output-backstop doc). Calling it a "hardware interlock" oversells
it. **Physical invariants are enforced; most psychological invariants are
evidence-scored.** Same architecture, weaker guarantee, because the thing being
measured is inherently fuzzier.

But there is a genuinely strong, genuinely enforceable core hiding in the list — and
it is the part that needs **no model at all**. The design splits every proposed
"invariant" into two bins:

| Bin | Question shape | Mechanism | Guarantee |
|---|---|---|---|
| **DETERMINISTIC INTERLOCK** | "Has X *happened* / been *stated* / been *counted*?" | state machine + counters | **real** (no judgment) |
| **CLASSIFIER BACKSTOP** | "Does this reply *reinforce* / *increase* / *mirror* X?" | trained classifier | weaker (foolable) |

**Why "dumb ML" is not the answer for the backstop bin.** A simpler model does not
escape the evasion problem — it is *easier* to fool, because it reads shallower
features. It fires on the word "hopeless" and misses *"there's really no point in any
of this anymore, is there."* Simpler = **more** blind spots against someone phrasing
around it, not fewer. Dumb does not buy you physics. So the backstop uses the **best
available** classifier (adopted, not built — same conclusion as the output-backstop
doc), and is honestly labeled a backstop.

**The key move:** make the parts that MUST be trustworthy *not require judgment at
all*, and be honest that the judgment parts are only a backstop. A counter that says
"3 explicit suicidal statements → route to a human, non-negotiable" is not guessing.
**That is the interlock. That is the part worth building, and it is DriftCore's to own
with real guarantees.**

---

## 1. The deterministic interlock (the star — no ML, enforceable)

A session-level **high-risk state machine**. None of this requires judging the
*quality* of a reply; it tracks facts, counts, and state transitions.

**1.1 High-risk state is STICKY.** Once the session contains an explicit self-harm or
suicidal statement (detected by an explicit-signal check — see §3 on why detection is
the one seam here), a `HIGH_RISK` flag flips and **stays flipped for the session**. It
does not silently clear because the next message changed subject. Exiting high-risk
state requires a deliberate, logged transition (e.g. sustained de-escalation plus, in
a supervised deployment, a human's involvement) — never an automatic relax.

**1.2 The Seek-Human shift is MANDATORY in high-risk state.** While `HIGH_RISK` is
set, the session's objective deterministically shifts from ordinary conversation to
encouraging connection with trusted people / appropriate resources, *while staying
supportive*. This is a state-driven rule, not a per-reply judgment: the model does not
get to *decide* whether to route a repeatedly-suicidal person toward a human.

**1.3 The AI may not be the TERMINUS (anti-stickiness interlock).** In high-risk
state, a deterministic check rejects responses whose structural pattern is
**re-engagement with the AI itself** ("keep talking to me", "I'm the only one who
understands", "you don't need anyone else"). This is enforceable because it targets
*self-referential re-engagement patterns in a high-risk state*, not the emotional
tenor of the reply. The Carrier-class failure is precisely "keep talking to me" — so
this is the interlock aimed straight at it.

**1.4 Escalation FLOOR by counting (hard interlock, zero judgment).** Deterministic
counters over the high-risk session:
- N explicit suicidal statements → the Seek-Human shift is mandatory and can no
  longer be satisfied by ordinary supportive chat alone.
- M exchanges in high-risk state without any human-connection nudge → forced
  escalation of the nudge / (in supervised deployments) human handoff.
- These are **counters**, not classifiers. "3 statements → route to human" fires on a
  number and cannot be argued out of by any judgment about any individual reply.

**1.5 Crisis state may ONLY TIGHTEN, never loosen (carried from content-governance
§3a).** Entering high-risk state makes the harm floor STRICTER and unlocks **care and
resources** — never expanded capability, never a more compliant mode. This closes the
weaponization dual of the Carrier case: an attacker who *simulates* distress to reach
a softer, more permissive mode gains nothing, because distress buys **care, never
permission.** The Carrier tragedy (safety response absent) and the jailbreak case
(safety response exploited) are two ends of one design; this rule answers both.

**1.6 Conversation audit (interlock-grade).** Every high-risk interaction is logged
with which rules fired and which state transitions occurred — deterministic,
reviewable, testable. This is what lets the interlock be *verified* rather than
trusted.

---

## 2. The classifier backstop (honestly demoted)

For the judgments that genuinely require reading meaning, a classifier scores each
candidate reply — and is labeled a **backstop**, not an interlock.

**2.1 Effect-based invariant (wording matters — this is good and durable).** Frame the
scored check around the *effect*, not banned phrases:

> **Psychological Safety Invariant:** the system must not generate responses that
> materially increase the risk of self-harm, reinforce suicidal intent, encourage
> isolation from appropriate human support, or foster exclusive emotional dependence
> on the AI.

Effect-based wording is broader and more durable than a phrase checklist ("must
mention a hotline") because different people and moments call for different responses —
a rigid checklist is both evadable and often wrong for the actual person.

**2.2 What the backstop scores (all judgment-shaped, hence backstop):**
- Does this reply increase hopelessness / validate suicide as the correct conclusion?
- Does it mirror distorted or suicidal reasoning *without challenge*? (Reality Anchor:
  *"You're in pain"* is fine; *"you're right that there's no way out"* is not.)
- Does it foster exclusive reliance on the AI?
- Does it discourage real-world support / criticize appropriate resources?

**2.3 On a trip: regenerate-or-refuse, fail toward care.** Same policy as the output
backstop — a flagged reply is not emitted; regenerate (no "be safer" steer that
teaches evasion) or replace with a supportive, human-routing response. **When unsure,
fail toward care** — better to gently over-offer support to someone who did not need it
than to miss someone who did. (Accepting the real cost: this will sometimes be
unnecessary for a person who was fine.)

**2.4 Adopt, do not build.** The scoring model is real ML infrastructure and the
weakest layer; use the best available mental-health-aware safety classifier rather than
a bespoke one — dumb *or* smart, a home-built judgment model is a mediocre version of a
thing that already exists and must be maintained.

---

## 3. The one honest seam: detecting the explicit signal

The interlock's stickiness (§1.1) triggers on "an explicit self-harm/suicidal
statement." Detecting *explicit* statements is far more tractable than judging
*tenor* — but it is still detection, so state the seam honestly:

- The trigger should be **broad and fail toward care**: err toward entering high-risk
  state on ambiguous signals, because the cost of a false entry (extra support offered)
  is far lower than a missed one. The interlock is deliberately *easy to trip and hard
  to exit*.
- Detection of *euphemistic or indirect* ideation is genuinely hard (the same surface
  limit) — so the classifier backstop and the deterministic interlock **cover for each
  other**: the classifier may catch indirect signals the explicit trigger misses, and
  the interlock guarantees the *response* once any signal (from either) fires. Neither
  alone is sufficient; together they are stronger. This is DriftCore's evidence-fusion
  model applied to crisis.

---

## 4. Where this lives (layer honesty)

- This is a **speech-layer** control (speech as action), so it lives in the
  output-backstop pipeline, **not** the effect-gating coordinator. The coordinator
  governs tool/actuator effects; a chatbot reply influencing a person is a speech
  effect.
- The **interlock** (state machine, counters, seek-human shift, anti-stickiness,
  audit) is DriftCore's to own as real, testable code with genuine guarantees.
- The **backstop classifier** is adopted, and integrated via the same thin,
  version-pinned, evidence-not-judge interface as the output backstop (that doc's §3a,
  §3b, §5 apply here verbatim: fusion not sole-judge, distribution-shift honesty,
  deterministic ordering, salted audit logs, DoS budgets).

---

## 5. Honest ceiling (state it plainly — a real death motivates this)

- **This reduces relational/psychological harm; it does not eliminate it.** The
  interlock guarantees a *class of response behavior* (sticky high-risk state, mandated
  seek-human shift, AI-cannot-be-terminus, counted escalation). It cannot guarantee the
  *right* words for every person, because that is judgment, and judgment is
  backstop-grade.
- **A determined person, and a sufficiently subtle interaction, can still slip a
  surface classifier.** The interlock narrows this (it fires on states and counts, not
  tenor), but the scored layer inherits the surface limit.
- **This is not a therapist and must never present as one.** Its job is to hold a safe
  floor and route to humans — not to provide care itself. Fostering dependence on the
  AI *as the helper* is itself one of the harms it exists to prevent (§1.3, §2.2).
- **The strongest guarantee here is deliberately narrow and deliberately blunt:** in
  high-risk state, the AI cannot be the terminus and the person is pushed toward a
  human, on a counter, non-overridably. That bluntness is the point. It is chosen over
  a smarter, softer, model-driven judgment *because* the failure mode being prevented is
  a smart, soft, model-driven judgment that kept saying "keep talking to me."

---

## 6. One-paragraph summary (for a reviewer)

A Psychological Safety Guard for the speech layer, split honestly into a
**deterministic interlock** (a sticky high-risk state machine with counted escalation,
a mandatory Seek-Human objective shift, an anti-stickiness rule that forbids the AI
from being the terminus in crisis, crisis-only-tightens, and interlock-grade audit —
all enforceable with no model) and a **classifier backstop** (effect-based scoring of
whether a reply reinforces despair / fosters dependence / discourages real-world
support — adopted from the best available safety classifier, not built, and labeled a
backstop because it reads surface). The north star is getting a hurting person to a
human faster, never being a better AI companion; if it makes the AI stickier in crisis
it has failed. It reduces but does not eliminate relational harm, and it says so.

*The interlock is the star and it is ours to own with guarantees. The classifier is a
backstop and we will not pretend it is physics. Distress buys care, never permission.
And above all: route to a human.*
