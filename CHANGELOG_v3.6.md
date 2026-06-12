# v3.6 Update — Changes for Manus to Push

## Summary
Adds the builder/maker path: DIY builders who have no factory behind
them can run DriftCore-protected machines safely, held to the SAME
standard of responsibility as a manufacturer — proven through
demonstrated competence, accepted responsibility, peer review, and
honest design reassessment. Red-team suite expanded to 38 attacks,
all passing at 100%.

## Why
v3.5 assumed a manufacturer always exists ("return to manufacturer").
For the home builder, that's meaningless — they ARE the manufacturer.
And the people who most need open-source safety are exactly those the
corporate model excludes. If the standard requires a factory, the
builder disables safety to function. v3.6 closes that gap.

## New files
- `driftcore/governance/builder_path.py`
  - BuildRecord — honest documentation of what was built and how it
    stays safe (the builder-path equivalent of factory docs).
  - ResponsibilityDeclaration — a named person signs acceptance of
    responsibility + honest competence attestation.
  - BuilderAuthority — registration (refuses incomplete records),
    operator/self-competence/peer approvals, and the severe-fault
    honest-design-reassessment protocol.

## Changed files
- `driftcore/verification/red_team_toolkit.py` — added 4 builder-path
  attacks (empty record refused, no self-review of serious faults,
  severe still blocks restart, forged signature rejected). 38 total.
- `CONSTITUTION.md` — Article VIII extended with the builder path.
- `SAFETY_CONTRACT.md` — added v3.6 builder/maker section.
- `README.md` — roadmap v3.6 marked done.

## Verification
```
python run_verification.py    # must print CATCH RATE: 100.0% (38/38)
python main.py                # must exit 0
```

## Suggested commit message
```
v3.6 — Builder/maker path: DIY safety without a factory

- Add BuildRecord, ResponsibilityDeclaration, BuilderAuthority
- Authority from demonstrated competence + accepted responsibility,
  standing equal to institutional (manufacturer/technician) authority
- Peer review replaces manufacturer sign-off for serious DIY faults
- Honest design reassessment for severe DIY faults ("I built this and
  it is not safe enough yet" — the builder's recall)
- Builder path cannot be used to skip safety: incomplete records
  refused, no self-review, severe faults still gated, signatures verified
- Extend Constitution Article VIII with the builder path
- Expand red-team suite to 38 attacks, all defended at 100%
- Makes "safety belongs to everyone" true for those without a factory
```

## Reminder
Revoke/rotate the PAT after pushing.
