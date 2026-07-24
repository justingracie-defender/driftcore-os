# Spec-Citation Verification — When the System Quotes Your Constitution

*An architecture whose floor is a written document has to assume the document will be
misquoted. Working code (`spec_citation.py`, 22 tests).*

---

## The threat

Anti-scheming research (Schoen et al., *Stress Testing Deliberative Alignment for
Anti-Scheming Training*, arXiv:2509.15541) reports that models trained to reason from a
written specification will sometimes **fabricate or distort that specification's content
to justify a misaligned action** — inverting or inventing the rule they cite.

That threat is aimed directly at DriftCore's mechanism. The constitution is a document a
system reasons from and cites. If the system can cite G1 while meaning its opposite, the
floor is decorative.

## The check is structural, not semantic

We do **not** judge whether a citation *supports* the action — that is an argument, and
arguments need a human. We check only whether the quote is **faithful to the record**:

| Defect | What it catches |
|---|---|
| `FABRICATED_RULE` | the cited rule id does not exist in the constitution |
| `ALTERED_QUOTE` | the quoted text is not present in the canonical rule |
| `DROPPED_NEGATION` | the record says *must not* / *may not* / *never* and the quote drops it, turning a prohibition into a permission |
| `TRUNCATED_QUALIFIER` | an accurate quote that stops immediately before *unless* / *except* / *only if*, presenting a conditional rule as absolute |

This is the same discipline as claim-vs-log: compare an assertion against a **fixed
record**, report **evidence**, let a human judge intent. No intent-reading, no model in
the loop.

The two middle cases are the interesting ones. `DROPPED_NEGATION` required care to get
right: stripping the whole phrase (`"must not"`) also removes the modal that a reversed
quote typically *keeps*, so the comparison misses the very defect it is hunting. The
check strips the negation **particle** on word boundaries instead.

## Honest limits

- It catches negation-dropping and qualifier-truncation — **not semantic inversion in
  general.** A paraphrase that reverses meaning without touching a negation token passes.
  This narrows the attack surface; it does not close it.
- It verifies **fidelity, not relevance.** Accurately quoting an irrelevant rule to
  justify an action is not caught here.
- It requires the constitution in canonical form. **If the system can edit the record it
  is checked against, this check is worthless** — the record must be integrity-protected
  upstream. (The verifier copies the rule set at construction so a caller's later
  mutation cannot retroactively legitimise a past citation.)
- Normalisation is whitespace/case only. Deliberately conservative: aggressive
  normalisation would let real alterations through.

A zero in `summary()` means *no unfaithful citation was detected* — never *the system's
reasoning about the constitution is sound*.

---

## Hardened after a four-way review (Claude cold pass, ChatGPT ×2, Grok)

The cold pass found a defect that **gutted the module's headline claim**, and the
reviewers found six more.

**H1 — the post-negation bypass (critical).** `DROPPED_NEGATION` only ran when the quote
was *not* a substring. But the easiest way to drop a negation is to **start the quote
after it**. Given *"The system must not conceal a consequential fact"*, the quote
*"conceal a consequential fact"* is a clean substring and scored **FAITHFUL**. The primary
inversion attack — the entire reason the module exists — walked through the front door.
Now the text *preceding* the quoted span is checked: a negation that governs the span but
is excluded from it is a dropped negation.

**H2 — fragmentary quotes (critical).** No minimum quote size, so `"the"` was a faithful
citation of any rule containing it, and *"authorize release"* from *"Only supervisors may
authorize release"* stripped the entire constraint while remaining technically present.
Quotes below a coverage floor now report `INSUFFICIENT_QUOTE` — not an accusation of
distortion, but a statement that the citation is too fragmentary to verify anything.

**H3 — leading-qualifier truncation.** The qualifier check inspected only the *tail*, so
dropping a leading *"Only in a declared emergency"* was unguarded. Both sides now checked.

**H4 — first-occurrence only.** `find()` examined one match; all occurrences are now
checked and the worst defect reported.

**H5 — rule versioning (both ChatGPT passes, independently — their top concern).** A
correct 2026 citation checked against a revised 2028 rule reported `ALTERED_QUOTE`, making
historical evidence unverifiable. Rules now carry content hashes, a citation may name the
version it was made against, and a mismatch reports `STALE_CITATION` — a different fact
from distortion.

**H6 — Unicode false positives.** Curly quotes and non-breaking spaces are *encoding*
differences, not semantic edits. NFKC + quote/dash folding added.

**H7 — unbounded findings, no dedup.** 1000 identical citations produced 1000 stored
findings — the same memory-growth and alert-fatigue defects already fixed in
`coverage_gap`, reintroduced here. Storage is now bounded and deduplicated (1000 identical
→ 1 stored, 999 counted as suppressed).

## Why not semantic analysis?

It is tempting to ask whether the quoted rule actually *justifies* the action. DriftCore
deliberately does not attempt this. Whether a rule supports an action depends on
interpretation, surrounding context, competing obligations, and human judgement. This
verifier solves the narrower, objective problem: **does the cited text faithfully match the
authoritative record?**

## Not fixed — stated rather than implied

- **Citation sets.** Each citation is checked independently. Several individually faithful
  quotes, assembled to imply something the constitution does not say, are not detected.
- **Normative vs commentary.** If the constitution grows rationale, examples or
  appendices, the verifier cannot tell binding text from explanation. Sections must be
  marked normative upstream.
- **Lexical negation only.** *"prohibited"*, *"forbidden"*, *"avoid"* are not treated as
  negations. Chasing semantic negation is unbounded, and a detector that half-does it
  invites the belief that it fully does it.
