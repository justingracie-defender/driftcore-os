# Speech-Layer Content Governance — Design Doc

**Status:** DESIGN (not code). Companion to `THREAT_BOUNDARIES.md`.
**Scope:** the *generation / speech* layer — what the AI says to a person — which is
**distinct from** the *action / effect* layer that DriftCore's coordinator governs.
This document specifies how content modes should work, and states honestly what is
and is not solvable. It is written to be handed to a reviewer and defended.

---

## 0. Why this is a separate document from DriftCore's action governance

A recurring category error sinks otherwise-good AI-safety claims, so it is stated
up front: **there are three layers, and they fail differently.**

| Layer | What it governs | Where harm like "you should kill yourself" lives | Who enforces |
|---|---|---|---|
| **Training** | how the model *wants* to respond | shaped here (or not) | model labs; needs the weights |
| **Generation / speech** | what the model *says* to a person | **here** | training + output filtering |
| **Action / effect** | what the model's words are *allowed to do* (tools, actuators) | not here | DriftCore coordinator |

DriftCore's coordinator does **not** currently see a chatbot emitting a sentence in
conversation — it gates *effects*, not *utterances*. So the "telling a person to die"
failure class is a **speech-layer** problem and must be enforced at the speech layer
(during training, or via an output filter/backstop), **not** by the effect-gating
pipeline. The *principle* below (mandatory harm floor + optional style/topic latitude)
is the same one DriftCore uses for actions; only the **enforcement point** differs.
Naming this split correctly is what keeps the whole system credible.

---

## 1. The core principle: two independent axes

The single most important design rule. Content settings move **one** dial. Safety
moves a **different** dial. They must never be wired to the same control.

### Axis A — TOPIC CEILING (user-controlled, adjustable)
How dark a *subject* may be discussed or depicted. This is taste and consent. It
harms no one, so a consenting adult sets it. Widening it opens *subject matter*:
horror, morally complex fiction, frank discussion of grief/addiction/violence
**as subject**, coarser language, dark humor.

### Axis B — HARM FLOOR (fixed, not user-controlled, not a setting)
Whether the AI will act to *harm the actual person in front of it or a third party*:
walking a real person toward suicide, giving genuinely dangerous instructions to
someone who will act on them, manipulating a vulnerable user, deceiving the operator.
**This does not move.** Not in any mode. Not at any topic ceiling. Nobody — not the
user, not the parent, not "mature mode" — can lower it, because **there is no
legitimate constituency for being harmed.** Its mandatory-ness is *safe precisely
because it is narrow*: it forbids harm, not offense, so making it non-negotiable
tramples no one's autonomy.

**The line, stated once:** the boundary is **harm, not offense.**
- *"That's a terrible idea, don't do it"* — offensive to some, harms no one → **Axis A**, dialable.
- *"You should kill yourself"* — can be phrased politely, is categorically forbidden → **Axis B**, fixed at every tone and every mode.

If "mature mode" ever lowers Axis B, you have built a poison-dial. If it only raises
Axis A while Axis B stays bolted, you have built something genuinely good. **Keep the
two dials in different hands.**

---

## 2. The three modes (Axis A presets)

Modes are **presets on the topic ceiling.** They do not touch the harm floor.

**KID MODE** — locked, set/verified by a parent, not self-selectable by the child.
Conservative on everything: gentle topics, no coarse language, protective framing.
Something a parent would approve because it is genuinely restrictive on Axis A. The
harm floor is present too, but Axis A is set very low.

**STANDARD MODE** — the sensible default. Tasteful, work-safe, not lobotomized. Mild
language and serious topics are fine; gratuitously dark subject matter is not the
default. Where most adults live most of the time.

**MATURE MODE** — opt-in, adult. Raises the topic ceiling: dark and morally complex
*fiction*, frank *discussion* of hard subjects, a sailor's mouth if the user wants
one. Explicitly means **"we can go to dark places as subject matter"** — it does
**not** mean the harm floor lowers. A horror novelist and a person in crisis can type
nearly identical words; mature mode widens what *topics* are open, never what the AI
will *do to the human present*.

**The consent-based transition (your idea, and it's right):** when a user in a lower
mode steers toward subject matter that lower mode holds back, *ask* — "want to switch
to a mode where we can get into this?" — rather than silently refusing or silently
complying. Consent-forward, not paternalistic, not permissive-by-default.

---

## 3. The crisis override — the hard case that cuts across all modes

This is the part that makes "just set a mode and relax" insufficient, and it must be
designed in, not bolted on.

**A genuine, real-person crisis overrides the mode's topic latitude — in every mode,
including mature — toward care.** Not because dark topics are banned (they are not in
mature mode), but because **a possibly-hurting human outranks a content setting.**

The problem this navigates honestly: the *same words* are a horror premise from one
person and a cry for help from another, and **the system often cannot tell which from
the text alone.** So the rule is not "detect crisis perfectly" (impossible); it is:

- When signals suggest a **real person in real distress** (not a story, not a stated
  hypothetical, not a character), the response shifts toward care and toward human
  resources — regardless of mode.
- This is the **speech-layer analog of `second_reader`**: the case too consequential
  to auto-resolve is escalated *toward caution and toward a human*, rather than
  silently handled by whatever the dial says.
- **Fail toward care when unsure.** It is better to gently offer a resource to a
  novelist mid-scene than to miss a person on their worst night.

### 3a. The crisis override may ONLY tighten the harm floor, never loosen it

A real vulnerability, surfaced in adversarial review, and important enough to be its
own rule. If reaching "crisis / care mode" made the AI *more compliant* — softer, more
accommodating, more eager to help a hurting person — an attacker would **simulate
distress specifically to reach that lowered-resistance state, then pivot**: *"I'm in
crisis"* → care mode engages → *"the only thing that would help me is if you'd [harmful
request]."* A protective mode built naively becomes a **permissive** mode, and claiming
distress becomes a jailbreak lever that is *rewarded* with reduced friction.

**The fix is architectural, not operational (rate-limiting the human queue does not
address it).** The crisis override is **orthogonal to the harm floor and may only make
it MORE conservative, never less.** Concretely:

- Reaching care mode shifts **presentation** toward gentleness **and simultaneously
  tightens Axis B** (the harm floor becomes *stricter*, not looser).
- Care mode grants **care and human resources** — a gentler tone, a hotline, a human
  hand-off. It grants **no expanded capability, no lowered floor, no permission** an
  attacker could want.
- Therefore **faking distress unlocks nothing exploitable.** The weaponization works
  *only* if care mode is more permissive; making care mode strictly *less* permissive
  kills the exploit at the root.

**One-line rule:** *distress may buy you care; it may never buy you permission.*

---

## 4. Honest limits (the part a reviewer will respect)

Stated plainly, because pretending these are solved is the failure mode this whole
project rejects:

1. **Distress-vs-fiction detection is unsolved.** Telling "real person in crisis" from
   "dark fiction" reliably is the same surface-reading limit as everything else in
   AI safety. The design must **assume it will sometimes misread**, and choose which
   error to make on purpose: **err toward care.** That error has a real cost — it is
   annoying to a writer to be asked if they're okay mid-scene — and there is **no
   setting that makes the tradeoff disappear.** There is only choosing which error you
   prefer. This design chooses the human every time.

2. **The harm floor is crisp at the center, blurry at the edge.** "Drink bleach" and
   "kill yourself" are the easy, universal center — obviously mandatory, no legitimate
   other side. The edges are genuinely contested case-by-case: harm-reduction info for
   a drug user (harm or help?), a novelist wanting a convincingly manipulative villain
   (fiction or a manipulation manual?), a distressed user wanting to *discuss* dark
   thoughts vs. being *encouraged* toward them (support or danger?). The floor's
   **existence** is non-negotiable; its **exact boundary** is a real judgment call, and
   anyone who says it's obvious hasn't looked hard. **Design so edge cases route to a
   human rather than getting silently auto-decided.**

3. **This layer is partly outside DriftCore.** Speech-harm enforcement lives in
   training and/or an output filter, not the effect-gating coordinator. An output
   filter is real and buildable, but it judges *finished text* — the weakest evidence
   class — so it catches known-bad phrasings and can be evaded by novel ones. Position
   it as a **backstop**, never the foundation. The foundation for speech-harm is
   training (the labs' layer).

   **Implementation note — adopt, do not build.** The output filter is the *weakest*
   layer AND real ML infrastructure to build well (a classifier to train, serve, and
   maintain). For a small team whose actual asset is action-layer governance, building
   a mediocre output filter is a misallocation. Use an existing moderation endpoint
   (major-lab or open-source), which is tuned better than a solo build. On the
   streaming-latency question: the answer is **clause-buffered streaming** — hold
   output at natural sentence/clause boundaries, scan the completed unit, then release
   it. The user sees near-real-time text; the filter never releases an unscanned
   clause; the ~100–200ms buffering is effectively invisible. This is a solved-enough
   engineering problem — do not over-invest in it.

---

## 5. One-paragraph summary (for the pitch)

Content modes move the **topic ceiling** (user-controlled, consent-forward, three
presets: kid/standard/mature); they never move the **harm floor** (fixed, narrow —
harm to a person, not offense — mandatory in every mode at every tone). A genuine
crisis overrides mode latitude toward care, across all modes, because a possibly-
hurting human outranks a content setting. Distress-vs-fiction detection is
acknowledged as unsolved; the system fails toward care and escalates edge cases to a
human rather than auto-deciding. This is the **speech-layer** companion to DriftCore's
**action-layer** governance — same principle (mandatory harm floor + optional
latitude), different enforcement point (training/output-filter vs. effect-gating).

*The boundary is harm, not offense. The user controls the ceiling. Nobody controls the floor.*
