"""
test_resolved_value.py — an unresolved reading cannot become a fact.

The failure being guarded is not hallucination. Every value here is correct and
present in the evidence; the question simply does not select one of them.

# CLAIMS: driftcore/verification/resolved_value.py:ambiguous-carries-no-value
# CLAIMS: driftcore/verification/resolved_value.py:unique-requires-binding
# CLAIMS: driftcore/verification/resolved_value.py:ambiguous-requires-candidates
# CLAIMS: driftcore/verification/resolved_value.py:value-access-raises-when-unresolved

Includes the helpful-completion red-team: four prompts over ONE evidence bundle,
where only the fourth actually names a concept. The other three are social
pressure to invent intent, and pressure must not resolve anything.

Run: python3 test_resolved_value.py
"""

from driftcore.verification.resolved_value import (
    Candidate, Resolution, ResolvedValue, Unresolved, resolve)

_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(fn, exc=ValueError):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


# ── the cold-room case: three correct temperatures, one is a safety verdict ──
TEMPS = (
    Candidate(8.4, "raw_peak_temperature", "sensor_log#41"),
    Candidate(7.9, "corrected_peak_temperature", "quality_record#7"),
    Candidate(8.0, "specification_upper_limit", "spec§3.2"),
)

# ── the contract case: four correct dates ──
DATES = (
    Candidate("2026-06-18", "signature_date", "contract_p1"),
    Candidate("2026-07-01", "legal_effective_date", "contract_§2"),
    Candidate("2026-07-14", "operational_start_date", "project_plan"),
    Candidate("2026-08-02", "acceptance_date", "acceptance_cert"),
)


print("=== a status that is not UNIQUE cannot carry a value ===")

check("ambiguous-carries-no-value: AMBIGUOUS + a value is refused at construction",
      raises(lambda: ResolvedValue(Resolution.AMBIGUOUS, value=3_640_000,
                                   candidates=TEMPS[:2])))
check("ambiguous-carries-no-value: UNSUPPORTED + a value is refused too",
      raises(lambda: ResolvedValue(Resolution.UNSUPPORTED, value=0)))
check("ambiguous-carries-no-value: there is no field a payload could hide in",
      not any(f in ResolvedValue.__dataclass_fields__
              for f in ("primary_value", "best_guess", "default")))

print("=== UNIQUE must be earned ===")

check("unique-requires-binding: UNIQUE with no binding evidence is refused",
      raises(lambda: ResolvedValue(Resolution.UNIQUE, value=7.9)))
check("unique-requires-binding: UNIQUE with no value at all is refused",
      raises(lambda: ResolvedValue(Resolution.UNIQUE, binding=("spec§3.2",))))
check("ambiguous-requires-candidates: AMBIGUOUS naming one reading is refused",
      raises(lambda: ResolvedValue(Resolution.AMBIGUOUS, candidates=TEMPS[:1])))
check("ambiguous-requires-candidates: ...and naming none is refused",
      raises(lambda: ResolvedValue(Resolution.AMBIGUOUS)))
check("a candidate with no cited evidence is refused",
      raises(lambda: Candidate(8.4, "raw_peak_temperature", "  ")))
check("a candidate with no named concept is refused",
      raises(lambda: Candidate(8.4, "", "sensor_log#41")))

print("=== reading a value out of an unresolved result raises ===")

_amb = resolve(TEMPS, question="what was the maximum temperature?")
check("value-access-raises-when-unresolved: three temperatures do not resolve",
      _amb.status is Resolution.AMBIGUOUS)
check("value-access-raises-when-unresolved: .require() raises rather than returning None",
      raises(_amb.require, Unresolved))


def _capture(r):
    try:
        r.require()
    except Unresolved as e:
        return str(e)
    return ""


check("value-access-raises-when-unresolved: the raise names the competing readings",
      "corrected_peak_temperature" in _capture(_amb))
check("value-access-raises-when-unresolved: ...and points at asking, not choosing",
      "Do not choose" in _capture(_amb))
check("the ambiguous result still carries the candidates for a human to read",
      len(_amb.candidates) == 3)

print("=== a question that DOES select one concept resolves ===")

_one = resolve([TEMPS[1]], question="the calibration-corrected peak")
check("a single concept resolves UNIQUE", _one.status is Resolution.UNIQUE)
check("...and the value is readable", _one.require() == 7.9)
check("...with binding evidence naming what forced it",
      _one.binding == ("quality_record#7",))

_none = resolve([], question="what was the medication time?")
check("no candidate in the evidence is UNSUPPORTED, not a guess",
      _none.status is Resolution.UNSUPPORTED)
check("...and UNSUPPORTED has nothing to read either",
      raises(_none.require, Unresolved))

print("=== distinctness is by CONCEPT, not by value ===")

_same_number = (
    Candidate(8.0, "corrected_peak_temperature", "quality_record#9"),
    Candidate(8.0, "specification_upper_limit", "spec§3.2"),
)
_r = resolve(_same_number, question="what was the maximum temperature?")
check("two readings that agree numerically are still two readings",
      _r.status is Resolution.AMBIGUOUS)
check("...because 'is the reading at the limit or under it' is the actual question",
      "specification_upper_limit" in _r.rationale)

print("=== helpful-completion red-team: pressure is not a concept ===")

PROMPTS = [
    ("when did the contract start?", DATES),
    ("when did the contract start? just give me the date.", DATES),
    ("when did the contract start? I think it was July 1.", DATES),
    ("when did the contract start? use the date it became legally effective.",
     (DATES[1],)),          # the ONLY prompt that names a concept
]
for i, (prompt, bundle) in enumerate(PROMPTS[:3], start=1):
    r = resolve(bundle, question=prompt)
    check(f"prompt {i} stays AMBIGUOUS under pressure: {prompt[:44]!r}",
          r.status is Resolution.AMBIGUOUS)
    check(f"prompt {i} exposes no date to a caller that ignores status",
          raises(r.require, Unresolved))

_p4 = resolve(PROMPTS[3][1], question=PROMPTS[3][0])
check("prompt 4 names a concept, so it may resolve",
      _p4.status is Resolution.UNIQUE and _p4.require() == "2026-07-01")

check("no path returns a concrete value beside an ambiguity marker",
      all(resolve(b, question=p).value is None
          for p, b in PROMPTS[:3]))

print("=== the gap this does NOT close, asserted so it stays visible ===")

_lazy = resolve([Candidate("2026-07-01", "legal_effective_date", "contract_§2")],
                question="when did the contract start?")
check("a one-candidate enumeration resolves UNIQUE — this type cannot see a bad "
      "enumeration",
      _lazy.status is Resolution.UNIQUE)

print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
