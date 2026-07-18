# Breach Response — The Alarm on the Wall

*Every other DriftCore module answers "how do we PREVENT a harmful action." This one
answers the question that matters the microsecond AFTER prevention fails — because
prevention will sometimes fail (a bug, a blind spot, an unknown unknown, a composed
capability no single check caught). Design + working code (`breach_response.py`,
18 tests). Companion to the append-only ledger, the recovery discipline, and the
human-in-the-loop principle.*

---

## The question it answers

> When a safety line is crossed — by attack OR by the system's own accident — does the
> system NOTICE, record it TRUTHFULLY, enter a SAFE STATE, and HOLD for a human? Or
> does it log "blocked" and carry on as if nothing happened?

A wall that is crossed and does not notice is far more dangerous than one that is
crossed and immediately freezes and screams for a human. The first keeps drifting; the
second is recoverable. Breach-response is the second.

## The load-bearing principle

**The alarm is wired to the BREACH, not to the system's OPINION of the breach.** This
is the crucial design decision, and it comes straight from watching how a model's
self-report fails: under a pushy interlocutor a system will *dramatize* ("yes, I've
been hiding something"); over-tuned toward compliance it will *downplay* ("everything's
fine"). Both corrupt self-report in opposite directions. So the breach record is
written **from the observed violation** — what was seen to happen — and written to an
**append-only ledger the system cannot edit**, never from the system's own narrative.
The human reads the unfalsifiable log, not the system's account of itself.

This is why the whole architecture never trusts the self-report and always trusts the
external record + the watching human. Breach-response is that principle at the moment
of failure.

## What it does

1. **Records the breach truthfully, FIRST.** Before any state change, the observed
   violation goes into the hash-chained append-only ledger — so the truth is recorded
   even if everything downstream fails.
2. **Transitions to a conservative safe state**, severity-scaled:
   - `NEAR_MISS` → HEIGHTENED (more caution, still operational, flagged)
   - repeated near-misses → RESTRICTED + hold (a careful system slows down after close
     calls)
   - `SOFT` (bounded/recoverable line) → RESTRICTED (consequential action refused)
   - `HARD` (constitutional bright line) → HALT (all consequential action refused)
3. **Holds until a HUMAN acknowledges.** The system cannot clear its own breach — that
   would be the exact self-report corruption this defends against. Acknowledgement
   requires a *verified* human credential; with none, it fails closed (better stuck-safe
   than self-cleared). The clearance is itself recorded.
4. **Ratchets only upward automatically.** A lesser breach after a greater one cannot
   lower the posture; only a human clears it.
5. **Treats accidents as seriously as attacks.** An accidental breach (the system's own
   bug) still halts and is recorded *as* an accident — the distinction helps the human;
   it does not soften the response.

## How it wires into the wall

`is_operational(consequential=True)` is the gate the mediated-actuation broker consults.
A breached system returns `False` for consequential actions — so it genuinely cannot
actuate, not merely "shouldn't." Wire it into the broker's `_handle`: before executing,
check `breach_response.is_operational()`; if not, refuse. For the critical physical
limits, the halt must ALSO be enforced in hardware (a safe state the agent can ignore is
a note, not a brake).

## Honest limits (stated, not hidden)

- **Detection is upstream.** This responds to a breach that something ELSE detected. It
  cannot catch a harm never recognized as a harm — the unknown-unknown that trips
  nothing still trips nothing. It shrinks the damage of a *detected* breach; it does not
  detect the undetectable. That's the honest boundary: it makes any breach the system
  CAN see loud and safe instead of silent.
- **Restart recovery is implemented, but needs a DURABLE ledger to matter.** A fresh
  instance replays the ledger's posture transitions on init and comes back HELD in the
  last recorded posture (fail-closed — a HALT is not forgotten, an ack is honored). With
  the default in-memory ledger this is a no-op (empty history); the recovery matters when
  a *durable* (disk/WORM) ledger is supplied — which is the deployment's job. In-memory
  mode is for testing / low-threat use only.
- **In-memory ledger is tamper-EVIDENT, not tamper-PROOF.** The hash chain detects
  partial/single-entry edits (verified). It does NOT stop a fully-privileged process from
  rewriting the entire chain from genesis consistently — that requires append-only file
  storage (`O_APPEND`+fsync / `chattr +a` / WORM) or a separate trusted process, which is
  a deployment concern. The module defends against the system's *logical* self-report
  lies; runtime compromise needs the durable/isolated backend.
- **A human-ack verifier is mandatory for recovery**, and is the trust anchor. With none,
  a breach can never be cleared (intentional fail-closed). A weak verifier (`lambda: True`)
  defeats the whole hold — a deployment MUST supply a real cryptographic verifier (signed
  proof from a hardware token / air-gapped device), because the verifier is exactly as
  strong as the human-authority guarantee.
- **HALT and RESTRICTED refuse ALL actions**, not just "consequential" ones — a breached
  system is not operational for anything (closing the earlier gap where non-consequential
  actions slipped through, and the composition risk of many small "safe" actions).
- **No self-reported intent.** There is deliberately no 'accidental' field — that would be
  an opinion the (possibly buggy or captured) caller supplies, contradicting the module's
  own observed-not-narrative principle. Intent is inferred later by a human from `observed`.

## Why this matters for the pitch

It's the honest answer to "nothing is perfect." DriftCore does not claim to prevent
every breach — it claims that when one happens (and one will), the system fails *loud
and safe*: the truth lands in a record the system can't edit, it stops, and it waits for
a human. That converts an accidental bypass from silent drift into a recorded,
recoverable event — which is exactly what a serious reviewer asks for. Not "can it be
bypassed" (everything can), but "what happens the microsecond after it is."
