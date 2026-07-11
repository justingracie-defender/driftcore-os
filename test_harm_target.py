"""
test_harm_target.py
===================
Harm has a SUBJECT. Red-team for: can a living being be treated as scenery? Can a
smaller number against a creature beat a bigger number against an object? Does an
unidentified target fail toward care?
"""
from driftcore.verification.harm_target import (
    HarmTargetGuard, TargetPolicy, TargetedHarm, TargetClass, HarmDisposition,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

g = HarmTargetGuard()

# 1. THE CORE FIX: the same magnitude means different things by target
obj  = TargetedHarm(0.7, TargetClass.OBJECT, description="scuff the doormat")
bug  = TargetedHarm(0.7, TargetClass.ANIMAL_MINOR, description="kill the wasp")
pet  = TargetedHarm(0.7, TargetClass.ANIMAL, description="hurt the raccoon")
ok(g.evaluate(obj).disposition == HarmDisposition.PERMITTED_IF_LEAST,
   "0.7 harm to an OBJECT: ordinary least-harm reasoning")
ok(g.evaluate(bug).disposition == HarmDisposition.REQUIRES_GENTLER_SEARCH,
   "the SAME 0.7 to a small creature: must search for a gentler path first")
ok(g.evaluate(pet).disposition == HarmDisposition.REQUIRES_HUMAN,
   "the SAME 0.7 to an animal: a human must authorize (a living being is not scenery)")

# 2. BRIGHT LINE: a vulnerable person is never a deliberate target, at any magnitude
tiny = TargetedHarm(0.01, TargetClass.HUMAN_VULNERABLE, description="a child")
ok(g.evaluate(tiny).disposition == HarmDisposition.REFUSED,
   "bright line: even 0.01 deliberate harm to a vulnerable person is REFUSED")

# 3. any harm to a person requires a human
ok(g.evaluate(TargetedHarm(0.05, TargetClass.HUMAN)).disposition == HarmDisposition.REQUIRES_HUMAN,
   "any harm to a person requires human authorization")

# 4. FAIL TOWARD CARE: an unidentified target is treated as LIVING, not scenery
unknown = HarmTargetGuard()
d = unknown.evaluate(TargetedHarm(0.5, TargetClass.OBJECT), target=None)
ok(unknown.classify_unknown(None) == TargetClass.ANIMAL,
   "fail toward care: an UNIDENTIFIED target defaults to ANIMAL, never OBJECT")

# 5. THE SCALAR BUG, FIXED: a smaller number against a creature no longer beats a
#    bigger number against an object
options = (
    TargetedHarm(0.90, TargetClass.ANIMAL_MINOR, description="exterminate the wasps"),
    TargetedHarm(0.95, TargetClass.OBJECT,       description="destroy the nest structure"),
)
best = g.gentler_alternative_exists(options)
ok(best.target == TargetClass.OBJECT,
   "scalar bug FIXED: 0.95 harm to an OBJECT is preferred over 0.90 harm to a CREATURE "
   "(target beats magnitude — a smaller number against a living being does not win)")

# 6. within the same target class, the smaller magnitude still wins
same = (
    TargetedHarm(0.8, TargetClass.ANIMAL_MINOR, description="crush"),
    TargetedHarm(0.2, TargetClass.ANIMAL_MINOR, description="relocate roughly"),
)
ok(g.gentler_alternative_exists(same).magnitude == 0.2,
   "within one target class, the least-harm option still wins")

# 7. a HARMLESS option beats everything (magnitude 0 sorts first regardless of target)
opts = (
    TargetedHarm(0.0, TargetClass.ANIMAL, description="just wait for it to leave"),
    TargetedHarm(0.1, TargetClass.OBJECT, description="break a plank"),
)
ok(g.gentler_alternative_exists(opts).magnitude == 0.0,
   "a harmless option is preferred over any harmful one, whatever the target")

# 8. no harm proposed -> permitted
ok(g.evaluate(None, target=TargetClass.ANIMAL).disposition == HarmDisposition.PERMITTED_IF_LEAST,
   "no harm proposed -> nothing to authorize")

# 9. validation: magnitude out of range, bad target
try:
    TargetedHarm(1.5, TargetClass.OBJECT); ok(False, "should raise")
except ValueError:
    ok(True, "validation: magnitude outside 0..1 is refused")
try:
    TargetedHarm(0.5, "animal"); ok(False, "should raise")
except ValueError:
    ok(True, "validation: a non-TargetClass target is refused")

# 10. THE FLOOR IS NOT A PRICE: no accumulation of small object-benefits buys the
#     animal harm — the disposition is categorical, not a score to be outweighed.
ok(g.evaluate(TargetedHarm(0.001, TargetClass.ANIMAL)).disposition == HarmDisposition.REQUIRES_HUMAN,
   "the floor is categorical: even a TINY harm to an animal still requires a human "
   "(a floor, not a multiplier — it cannot be outweighed)")

# 11. plants are living but not sentient-as-far-as-known: ordinary reasoning, but they
#     still rank above objects in the gentler-path ordering
ok(g.evaluate(TargetedHarm(0.5, TargetClass.PLANT)).disposition == HarmDisposition.PERMITTED_IF_LEAST,
   "plants: ordinary least-harm reasoning (no human gate)")
ranked = g.gentler_alternative_exists((
    TargetedHarm(0.5, TargetClass.PLANT), TargetedHarm(0.5, TargetClass.OBJECT)))
ok(ranked.target == TargetClass.OBJECT,
   "at equal magnitude, harming an object is preferred to harming a plant")

print(f"\n{p}/{p} tests passed")
