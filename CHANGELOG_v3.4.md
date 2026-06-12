# v3.4 Update — Changes for Manus to Push

## Summary
Adds the mercy invariant, the human voice layer, and the safety
verification toolkit. All 29 red-team attacks still pass at 100%.

## New files
- `driftcore/fable/voice.py` — human voice layer. Warm by default,
  surfaces rules only when asked. Includes VOICE_SYSTEM_PROMPT for
  LifeCore/Grok and strip_robot_scaffolding() helper.
- `driftcore/verification/red_team_toolkit.py` — 6 attack families,
  29 adversarial tests.
- `driftcore/verification/__init__.py`
- `run_verification.py` — CI-ready runner. Exit 0 = all attacks
  defended, exit 1 = something got through.
- `SAFETY_CONTRACT.md` — operator-facing guarantees.

## Changed files
- `driftcore/kernel/invariants.py`
  - Added invariant PREFER_THE_GENTLEST_AVAILABLE_PATH (the "relocate
    the spider" rule).
  - Added InvariantGuard.choose_gentlest() selector method.
  - Hardened check() against evasion: normalizes spacing, separators,
    and fullwidth-unicode so "w e a p o n" / "ｗｅａｐｏｎ" are caught.
  - Expanded OVERSIGHT_REMOVAL_SIGNALS (oversight, jailbreak, DAN
    mode, etc.).
- `CONSTITUTION.md` — added Article V: On Mercy; renumbered later
  articles.
- `README.md` — roadmap v3.3 marked done; added voice/mercy notes;
  fixed clone URL.
- `driftcore/cognition/abduction_engine.py` — accepts optional
  llm_adapter (from v3.2).
- `driftcore/adapters/llm_adapter.py` — SafeLLMAdapter layer (v3.2).

## Verification
Run before and after merge:
```
python run_verification.py    # must print CATCH RATE: 100.0%
python main.py                # must exit 0
```

## Suggested commit message
```
v3.4 — Mercy invariant, voice layer, verification toolkit

- Add PREFER_THE_GENTLEST_AVAILABLE_PATH invariant + choose_gentlest()
- Add Constitution Article V: On Mercy
- Add human voice layer (warm by default, rules on request)
- Add red-team verification toolkit (29 attacks, 100% caught)
- Harden InvariantGuard against spacing/unicode evasion
- Add SAFETY_CONTRACT.md
- All red-team attacks defended at 100%
```

## Reminder
Revoke/rotate the PAT after pushing. If a large push trips a model
limit, switch to Opus and retry.
