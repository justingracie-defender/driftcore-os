# v3.5 Update — Changes for Manus to Push

## Summary
Adds embodiment classification and tiered, signed, role-based restart
authority — fixing the biggest weakness ChatGPT's red-team identified
(release authority was trust-based). Red-team suite expanded to 34
attacks, all passing at 100%.

## New files
- `driftcore/governance/__init__.py`
- `driftcore/governance/embodiment.py` — EmbodimentClass
  (SOFTWARE_ONLY / REMOTE_PHYSICAL_CONTROL / EMBODIED). The top-level
  branch: "can this system cause irreversible physical harm?" Determines
  which safety subsystems activate. Class locks at startup so a running
  system cannot downgrade itself to shed safety rules.
- `driftcore/governance/restart_authority.py` — tiered restart approval.
  Signed approvals (verified identity, not trusted strings), role-based
  (OPERATOR/TRAINED/TECHNICIAN/MANUFACTURER), multi-party, must be
  different people, scaled by severity AND embodiment class. Always at
  least one achievable path (incl. remote manufacturer sign-off and
  return-to-maker).

## Changed files
- `driftcore/verification/red_team_toolkit.py` — added 5 restart-authority
  attacks (operator-only block, dual-role block, severe return-to-maker,
  forged signature, embodiment-downgrade block). Now 34 attacks total.
- `driftcore/safety/safe_halt.py` — release() annotated: simple string
  release is for MINOR/software only; serious cases must use
  RestartAuthority.
- `CONSTITUTION.md` — added Article VIII: On Bodies and Restart.
- `SAFETY_CONTRACT.md` — added v3.5 tiered restart authority table.
- `README.md` — roadmap v3.5 marked done.

## Verification
```
python run_verification.py    # must print CATCH RATE: 100.0% (34/34)
python main.py                # must exit 0
```

## Suggested commit message
```
v3.5 — Embodiment classes + tiered signed restart authority

- Add EmbodimentClass: SOFTWARE_ONLY / REMOTE_PHYSICAL_CONTROL / EMBODIED
- Branch all physical-safety logic on ability to cause irreversible harm
- Replace trust-based release with signed, role-based, multi-party
  restart authority scaled by severity and embodiment class
- Roles: operator (authority) + technician/manufacturer (competence)
- Always an achievable path: trained neighbor, remote maker sign-off,
  or return-to-manufacturer; severe physical faults = return-to-maker
- Add Constitution Article VIII: On Bodies and Restart
- Expand red-team suite to 34 attacks, all defended at 100%
- Addresses external red-team feedback on release authority
```

## Reminder
Revoke/rotate the PAT after pushing.

## Still ahead (from external red-team feedback — future versions)
- Drift threshold validation (research: do scores correlate with danger?)
- Deeper detector robustness (cross-session, multi-step decomposition)
- Real hardware interlock integration (needs hardware testers)
- Full cryptographic signing (current signatures are hash-based stand-ins
  for real hardware keys / passkeys)
