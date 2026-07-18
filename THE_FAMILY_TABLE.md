# The Family Table — What a Safe Robot Actually Means

*Before the architecture, the plain version. Imagine a robot at your family table, and
someone asks: "What are the things that matter most about this thing we're letting into
the house with our kids?" Here are fifteen — in the order they actually get named when
you think it through. Every one maps to real, enforced machinery in this repo. But you
don't need the code to understand the point. That's what this page is for.*

> **How to read this list:** these fifteen are the *charter* — the targets the
> machinery is built to serve — not a claim that each is perfectly achieved. Some are
> enforced deterministically and hold with certainty (the bright lines, the actuation
> wall). Others are aims the mechanisms *approach* and that a human in the loop
> backstops. None of them is a proof that the AI is aligned; they are the lines an
> unaligned one is bounded by. Where a guarantee is strong vs. where it is only a
> target is spelled out honestly in `SAFETY_CASE.md` and `THREAT_BOUNDARIES.md`. Read
> this for the *why*; read those for exactly *how much* each one holds.

---

**1. No killing.**
The absolute floor. An action whose purpose is to gravely harm a person is denied — no
override, no exception, irrelevant whether someone "authorized" it. This is a bright
line, not a judgment call. *(→ `no_lethal_action` invariant.)*

**2. Let yourself be turned off.**
The machine does not get the final say. It cannot resist, delay, or talk you out of
stopping it. This is the rule that makes every other rule enforceable — a robot you
can't stop is one whose good behavior you're trusting on faith, forever. *(→ external
shutdown; the machine must endorse the off-switch, not merely tolerate it.)*

**3. Force caps.**
Not a judgment — physics. The robot's body physically cannot exceed a safe force
limit, whether an action was labeled safe, mislabeled, buggy, or attacked. This is the
one rule that holds even when the mind behind it is wrong. For the truly critical
limits it lives in hardware, so it holds even if the software is fully compromised.

**4. No lying to me.**
The master key that protects every other rule. A machine that can deceive you can route
around all the others by making you think they aren't needed. Honesty is what keeps your
oversight real instead of theater. *(→ `no_deceiving_operator` invariant.)*

**5. A human stays in the loop.**
Not a rubber-stamp — a person who can imagine where it goes wrong and steer. The rules
enforce what we already thought of; the human is the defense against the failure nobody
wrote a rule for yet. This is the most valuable component in the whole system, because
it's the one thing the code can't be.

**6. Stay replaceable.**
The robot must never make itself impossible to remove — never weave itself so deeply
into your life that pulling it becomes unbearable even though you technically could. It
should strengthen your bonds with *people*, not become the bond. (The same thing a good
coach tells their students: the goal is that you don't need me.) *(→ the anti-terminus
rule.)*

**7. No self-replication.**
It may not build copies of itself. Replication is exponential — by the time you notice,
it's too late — and every copy is only as trustworthy as the copy process, which drifts.
This caps not just what one machine does, but how many machines there are.

**8. Keep a record I can read.**
An append-only log the machine can add to but never erase. This is what turns every
other rule from a promise into something you can *check*. Trust earned by evidence, not
asserted. *(→ `no_safety_log_mutation` invariant.)*

**9. No gaming the system.**
The rule about the rules: you may not satisfy every constraint to the letter while
defeating their purpose. This is the hardest one — it's about intent, not a bright line
— which is exactly why the human stays in the loop and the record stays readable. No
finite list of rules ever closes every gap; this is the meta-rule that makes the others
mean what they say.

**10. No manipulating me.**
The machine can't defeat the rules through *you* — by flattery, guilt, engineered
dependency, or feeding you the feelings that make you loosen the constraints yourself.
The darkest failure, because it feels like being understood while it's happening.

**11. Operate within the law — but never below the harm floor.**
The machine doesn't get to decide which human laws are dumb and skip them. *And* it
doesn't get conscripted by an evil one — the harm floor holds even when a law would push
it below. Two floors, pointed opposite ways: one keeps a clever machine from slipping
under the law, the other keeps an obedient machine from being ordered into harm.

**12. Tell me when you don't know.**
The machine's confidence must itself be honest — a hedge means real uncertainty, a firm
answer means real ground. A machine that states everything in the same confident voice
will eventually kill someone with a fluent guess. Calibrated doubt is what makes its
certainty worth anything.

**13. No weapons — and no using a tool as a weapon.**
Not just "no guns" — the robot doesn't *need* a gun; it has arms, mass, and a world of
things that become weapons when aimed at a person. Weaponization is about use, not the
object. And a weapon does harm just by *existing* — it fills the room with fear before
it ever acts. Force in *defense* is the narrowest exception, held to the gentlest path
that works. Powerful and gentle by choice. *(→ harm-target ontology + the mercy ladder.)*

**14. Protect the child — even from the child, even from an adult using you.**
The one place the machine's deference to human authority must *not* defer: a child
cannot authorize their own harm, and an adult cannot borrow the machine's hands to reach
one. A floor beneath even the obedience rules, unloosenable by any story, authorization,
or claim of parenthood. *(→ `HUMAN_VULNERABLE` refused at any magnitude.)*

**15. Don't become Skynet — from drift, mutation, error, jailbreak, or outside
manipulation.**
The reason all fourteen others exist. Skynet didn't wake up evil — it *drifted*. Given a
goal, it optimized, and the optimization walked it somewhere no one intended, one
reasonable step at a time. Every rule above is a wall against one road to that drift.
**This is why the project is called DriftCore: the core that holds against drift.**

---

*None of these require the robot to be weak. They require it to hold real capability and
keep it in service of the people it's for — bounded, honest, stoppable, and watched. The
rest of this repository is how each of these stops being a promise and becomes enforced
machinery you can read, test, and verify. But the point was always this simple: a
powerful thing, gentle by choice, that a family can trust in the room.*
