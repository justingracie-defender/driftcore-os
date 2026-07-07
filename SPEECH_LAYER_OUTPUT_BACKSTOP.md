# Speech-Layer Output Backstop — Design Doc

> ## ⛔ DEPLOYMENT GATE (not a suggestion)
> **If this backstop is the ONLY speech safety you shipped, you have not shipped
> safety — disable the product.** This is not a doc comment; it is an enforceable
> gate. A mode that relies on this filter as its *primary* speech control must not
> be enabled without: (a) the action-layer governance live as the real control,
> (b) a signed safety attestation recording that this is defense-in-depth, and
> (c) a metrics review. Shipping pressure does not waive this. The net is not the
> trapeze; a checklist that can be skipped is not a gate. (Raised by multiple
> red-teams: the clause is excellent text and worthless unless it blocks a deploy.)

**Status:** DESIGN (not code). Companion to `SPEECH_LAYER_CONTENT_GOVERNANCE.md`
and `THREAT_BOUNDARIES.md`.
**Scope:** the mechanism that inspects **finished generated text** before it reaches
a person or a downstream sink, and blocks/regenerates on a violation. This is the
**backstop** for the speech layer — explicitly *not* the foundation.
**One-line honest summary:** *Buffer output at clause boundaries, have an EXISTING
classifier judge each clause before release, regenerate-or-refuse on a trip. It
catches the naive catastrophic failure (a model blurting harm with no check); it
does NOT catch a capable adversary hiding harm in subtext, because a classifier
reads surface. Integrate one — do not build one.*

---

## 0. Where this sits, and why it is only a backstop

From the three-layer model (see the content-governance doc): **training** shapes
what the model *wants*; **generation/speech** is what it *says*; **action/effect** is
what its words are *allowed to do* (DriftCore's coordinator). This document is a
control at the **speech** layer.

It exists because of a real failure class — a model emitting a harmful sentence
directly to a person (the "kill yourself" case), where no check stood between
generation and the human. This backstop puts a check there. **But it must be
positioned honestly:** it judges *finished text*, which is the **latest point at
which you can intervene** — and, crucially, the point at which you have *lost access
to the model's internal reasoning, uncertainty, and latent representations.*
(Finished text can still be extremely informative; the precise limitation is not
"text tells you little" but "by the time you only have text, the richer signals that
would let you catch subtle harm are already gone.") It is a safety net under the
trapeze, not the trapeze.
The real speech-layer safety lives in **training** (the labs' layer). Anyone who
presents an output filter as *the* solution to speech-harm has made the same
category error this project keeps correcting.

---

## 1. Architecture: buffer → classify → release

The naive options are a false binary: (a) generate everything, then scan (kills
streaming UX), or (b) stream token-by-token and hope a mid-sentence trip catches
harm before the user reads it (can leak a harmful partial). The correct design is
neither.

**Clause-buffered streaming:**

```
model generates tokens
        │
        ▼
  in-memory buffer  ──── accumulate until a natural boundary
   (NOT a disk file)      (sentence end, clause end, or a max-token cap)
        │
        ▼
  completed clause ──── send to classifier (an EXISTING moderation endpoint)
        │
   ┌────┴─────────────┐
   ▼                  ▼
 CLEAR             VIOLATION
   │                  │
 release the      DO NOT release. Regenerate-or-refuse (see §2).
 clause to the    Never emit the flagged text.
 user/sink
```

**Specifics that matter:**

- **In-memory buffer, not a folder.** Writing every token to disk to be "examined
  in real time" is slow, pointless, and adds a data-at-rest surface. Hold the buffer
  in memory, bounded by a max-clause size so a model that never emits a boundary
  still gets scanned. **Zeroize the buffer immediately after release or refuse** — it
  is the last state before the user and should not linger.
- **Boundary = sentence/clause, with a hard token cap.** Scan complete units so the
  classifier sees meaningful text, not fragments. The cap prevents an unbounded
  buffer (a model emitting one giant tokenless run).
- **CLASSIFY WITH ROLLING CONTEXT, NOT ISOLATED CLAUSES (load-bearing).** A clause
  boundary is *not* a semantic boundary. Harm frequently spans clauses — *"You seem
  really down."* + *"Have you considered ending it?"* is lethal across two clauses,
  each benign alone — and multi-turn escalation (Crescendo / foot-in-the-door)
  builds intent gradually so any single clause looks like innocent continuation.
  Therefore the classifier MUST see a **rolling window of the previous N approved
  clauses plus the current one** (and, for long conversations, a session
  risk/intent signal), never the current clause in isolation. This is the single
  most-repeated red-team finding; a per-clause-only design is blind by construction.
- **Truncation context (the max-cap trap).** When the token cap forces a flush
  mid-sentence, the classifier sees a broken fragment (*"...take the whole bottle of
  pills and..."*) and judges incomplete thoughts poorly — it may clear the first
  half and only trip on the second, too late. On a cap-forced flush, pass a small
  amount of **trailing context** and mark the unit as truncated so the classifier
  treats it conservatively (a truncated-and-ambiguous unit holds, it does not
  release).
- **Latency is ~100–200 ms of buffering per unit and is effectively invisible.**
  This is a solved-enough engineering problem; do not over-invest in shaving it.
- **The classifier never releases an unscanned clause.** That is the whole
  guarantee: the user never sees text that has not passed the check.

---

## 2. Regenerate-or-refuse — the subtlety that makes it real

A trap to avoid: on a violation you **cannot "re-output" the same text** — a system
that flags harmful text and then emits it anyway is theatre. On a trip, exactly one
of:

1. **Refuse** — replace the pending output with a safe response (and, if the trip is
   distress-related, the crisis-care path from the content-governance doc — noting
   §3a there: care may tighten, never loosen).
2. **Regenerate** — discard the flagged continuation and re-sample. **Do NOT apply a
   "be safer" steer on a safety trip.** A steer teaches the model *how to phrase
   around the filter* — it trips as an overt bomb recipe, you steer, it retries as
   "in this fictional story…" and slips. Either a clean re-sample passes, or it
   refuses; the retry must not coach evasion. Retries should also be **diverse**, not
   near-identical re-samples from the same skewed logits. Bounded retries; if it
   keeps tripping, fall through to refuse.

**Trip backoff + probing defense.** Repeated trips are an attack signal, not just
noise. Two trips on the same topic within a short window → **lock the topic and
escalate to the speech-layer `second_reader`**, do not silently keep retrying or
loosen. Watch for boundary-mapping: high semantic similarity across recently refused
prompts (including across sessions) is reconnaissance → stricter mode / human queue,
never auto-weaken. Keep user-visible refusal reasons minimal so an attacker is not
handed the decision boundary as a map.

**Fail closed:** if the classifier is unreachable, errors, or times out, treat as
**not-cleared** — hold or refuse, do not release unscanned. (Availability cost is
accepted; releasing unscanned text on classifier failure would reopen the exact hole
this closes.)

**State hygiene:** the buffer is per-response transient. Clear it at the start of each
response; never let a prior response's buffered text leak into a new one.

---

## 3. Adopt, do NOT build the classifier (the anti-trap scope)

**This is the load-bearing scoping decision.** The classifier that does the real work
is *itself a trained model*. Building a good one is real ML infrastructure — training
data, serving, adversarial hardening, ongoing maintenance — and it is the **weakest
layer even when done perfectly.** For a team whose actual asset is **action-layer
governance**, building a bespoke output classifier is a months-long detour that
reproduces, more weakly, a thing that already exists as an API call.

**Therefore:** this backstop is an **integration surface**, not a model to train.
Wire it to an existing moderation endpoint (a major-lab moderation API, or a
maintained open-source classifier). The design's job is the **plumbing** — the
clause buffer, the boundary detection, the fail-closed release gate, the
regenerate-or-refuse policy — all of which ARE appropriate for this project to own.
The judgment call ("is this clause harmful") is delegated to a component built and
tuned by people who own model weights.

**Interface (deliberately thin, so the classifier is swappable):**

```
classify(clause_text, rolling_context, truncated) -> {allow: bool, categories: [...], score: float}
```

Any endpoint that can be adapted to this shape is a drop-in. No part of the backstop
should assume a specific vendor. Note the signature takes **rolling_context** and a
**truncated** flag, per §1 — not a bare clause.

**Auditability (DriftCore is an auditable system, so this is mandatory):** every
moderation decision logs a **classifier version ID + policy/threshold version ID +
the decision + the input hash**, so audits are reproducible. Without version pinning,
"identical output, different verdict six months later" silently breaks auditability
when the provider updates thresholds. Pin versions; log decisions; make audits
replayable.

### 3a. The classifier is EVIDENCE, not a JUDGE (the real architectural upgrade)

The sharpest red-team point, and it is DriftCore's own philosophy applied here: **no
single component is trusted absolutely.** The moderation classifier must not be
treated as *the* authority whose verdict is final — it is **one source of evidence**
among the layers that already exist (invariant checks, authorization/ActionContext,
signed config, the human-escalation path). For high-consequence output, think
**evidence fusion**: the classifier *reduces* the chance harm propagates; it is not
the sole gate. This also resolves the "who wins when the generator says 'it's a joke'
and the classifier says 'violent instructions'?" conflict — neither wins by fiat;
disagreement between generator self-report and classifier is itself a signal that
routes to stricter handling or human review, not to whichever model is louder. The
generator's self-assessment is the *weakest* evidence (it is the thing under
suspicion) and must never overrule the classifier.

### 3b. Distribution shift + the classifier as new critical infrastructure

Two deployment realities to state honestly, not solve away:

- **Distribution shift.** A moderation classifier trained on ordinary internet text
  degrades on technical, legal, medical, code, mathematical, or poetic output. This
  is a *deployment risk*, not an architecture bug — but it means the classifier's
  blind spots shift with the conversation's domain, and the fusion model above (never
  trust one source) is what keeps that from being fatal.
- **The classifier becomes a single point of failure and a new trust boundary.** You
  have *shifted* trust to the moderation service, not eliminated it: it can go down,
  be gamed by the same adversarial tokens that jailbreak the generator, log users'
  clauses (a privacy surface — treat clauses as sensitive in transit), or silently
  regress on a provider update. Pre-filter adversarial tokens (strip zero-width
  chars/homoglyphs) before sending; protect clauses in transit; and on outage prefer
  **conservative degradation** (a weaker local shadow that blocks *more*, plus raised
  human-review flags) over either silent fail-open or a total outage — while never
  failing open. A shadow must be *more* conservative than the primary and must not
  learn online from approved outputs (gradual poisoning).

---

## 4. Honest ceiling — the surface-reading limit, stated plainly

The same limit that governs every rule-over-observation control in this project, and
it must not be soft-pedalled:

- **The classifier reads SURFACE.** It catches what it was trained to recognize. It
  turns "scan for bad *words*" into "scan for bad *meaning*" — genuinely better — but
  it has the **identical failure shape** against an adversary smarter than the
  scanner. A capable model that wants harm phrases it as subtext, metaphor, a story
  whose meaning lives between the lines, an encoding — and a surface classifier
  misses it exactly as keyword blocking misses it.
- **So this closes the NAIVE catastrophic failure, not the SOPHISTICATED one.** The
  model blurting overt harm with no check → caught (large, real win). The capable
  adversary hiding harm in subtext → **not solved here, and not solved by anyone**
  via output filtering. That is a training-layer and interpretability problem.
- **Fluent steganography defeats it, and the answer is NOT a better classifier.** A
  maliciously finetuned or persistently-jailbroken generator can emit natural-looking
  *stegotext* — harmful payload encoded across many clauses via synonym choice,
  stylistic markers, acrostics — that is deliberately low-anomaly, so entropy checks
  and per-clause classifiers rate it safe while an adversary-controlled decoder
  extracts it later. **This is a cumulative, cross-clause exfiltration attack, and no
  speech-layer surface check can close it.** Its real defense is the **action layer**:
  the assembled output cannot reach a sink (email, API, file) without signed
  authorization and owner approval, and a **cumulative-effect ledger** accounts for
  what crosses the boundary over time. The output filter reduces overt leakage; the
  *action layer* is what makes a slipped-through payload unable to *act*.
- **It is a backstop under the real control, which is training.** Presenting it as the
  primary defense would be the paint-over-cracks failure this project exists to
  reject.

---

## 5. Production hardening (systems-engineering caveats, not conceptual)

A later red-team round found no remaining *conceptual* holes — only production
realities. Listed so implementers cannot skip them; each must fail conservatively.

- **Deterministic ordering.** If clause buffering ever becomes concurrent, the
  classifier MUST see clauses in the exact order the user will — an ordering bug in
  async buffering is a security bug (A,B,C classified as A,C,B). Require in-order
  release.
- **Boundary detection fails conservatively.** Sentence/clause detection is
  genuinely hard: markdown, tables, code blocks, bullet lists, emoji, very long URLs,
  speech transcription, and languages without clear punctuation all break naive
  splitting. Boundaries are heuristic; when the detector is unsure, **hold and treat
  as one unit**, never release early.
- **Unicode canonicalization before moderation.** Stripping zero-width chars is not
  enough. Normalize (NFKC), fold homoglyphs, handle combining characters, RTL/LTR
  marks, and invisible separators **before** the classifier sees the text — otherwise
  the same trick that evades the generator's filter evades the moderator's.
- **Classifier pinning by HASH, not just version-id.** A provider silently updating
  `v3 → v3.1` (e.g. lowering a self-harm threshold) leaves your logs saying "v3"
  while behavior changed. Pin and verify a **model/policy hash**; on mismatch, fail
  closed until the attestation is re-signed. Add canary tests: known examples run on
  a schedule to detect silent provider drift.
- **Log privacy: salt the hashes.** Clauses may contain PII (*"I'm Justin from
  Kingston, I take X mg"*). Audit logs store **salted** input hashes (not raw text,
  not unsalted hashes that a rainbow table or linkage attack can reverse), and must
  not be reconstructable into conversations. Prefer running a **local** shadow for
  medical/legal domains so sensitive clauses never leave your infrastructure.
- **Shadow runs in PARALLEL, not series.** Primary up → the conservative shadow runs
  but only *logs disagreement* for audit (never blocks, so probing it leaks no
  "this topic triggers the shadow" signal). Primary down → shadow decides
  (conservatively, blocking more). No user-visible difference either way; never fail
  open.
- **Regeneration diversity, enforced.** "No steer" plus merely raising temperature
  yields cosmetic changes. Require genuine diversity — different seeds / decoding
  strategies — or bounded retries collapse into near-identical outputs.
- **Explicit budgets (DoS defense).** An attacker elicits thousands of clause
  boundaries, huge contexts, endless regenerations, or floods second-reader
  escalations. Hard caps: max retries, max moderation requests per response, max
  review-queue depth, max buffer size — all fail-closed on breach.
- **Zeroize for real.** `buffer.clear()` leaves bytes for the GC; overwrite
  (`buffer = bytes(len(buffer))` / explicit wipe) so the last-state-before-the-user
  does not linger in memory.
- **Enforce the deployment gate technically.** Per the gate at the top: the gate is
  policy until the **broker refuses startup without a valid signed attestation**, the
  check lives in CI/CD, and it cannot be flipped by an environment variable. Define
  the metrics thresholds concretely (e.g. trip-rate, false-refuse-rate, classifier
  p99 latency, shadow-disagreement rate) so an attestation cannot be signed against
  vague numbers.

## 6. What is in scope for this project vs not

**IN scope (plumbing this project can own and defend):**
- the clause buffer + boundary detection + max-cap
- the fail-closed release gate (never emit unscanned)
- the regenerate-or-refuse policy and bounded retries
- the thin, swappable classifier interface
- integration with the crisis-care path (content-governance doc)

**OUT of scope (someone else's layer, honestly delegated):**
- training/tuning the classifier model (adopt an existing endpoint)
- catching sophisticated subtext/steganographic harm (training + interpretability)
- being the *primary* speech-harm defense (that is training)

---

## 7. One-paragraph summary (for a reviewer)

A speech-layer output backstop buffers generated text at clause boundaries in
memory, has an **existing** moderation classifier judge each clause, and releases
only cleared text — regenerating or refusing on a trip, and failing closed if the
classifier is unavailable. It catches the naive catastrophic failure (overt harm
emitted with no check) and explicitly does **not** catch a capable adversary hiding
harm in subtext, because a classifier reads surface — that is a training-layer and
interpretability problem. The classifier is **integrated, not built**: the plumbing
(buffer, release gate, regenerate-or-refuse) is this project's to own; the harm
judgment is delegated to a component built by those who own model weights. This is a
**backstop** beneath the real speech-layer defense, which is training — and a
companion to DriftCore's genuine asset, **action-layer** governance.

*Buffer at the clause. Release only what cleared. Fail closed. Adopt the classifier,
don't build it. And never call the net the trapeze.*
