# Artifact-channel evidence

`final-source-snapshot.json` identifies the starting archive and the final source
snapshot. `final-full-suite.log` and `baseline-full-suite.log` come from separate
fresh extractions. Their `.exit` files contain the real exit status (both 1), not
a status read through a logging pipeline. `final-checks.json` records all 18
commands, elapsed times, exits and output tails. Full output is saved per check.

`final-artifact-tests.log` reports 31/31. Final artifact/boundary/policy/authority
control directories contain 6/4/4/5 healthy, removed and restored test logs plus
summaries. The removal script requires intended assertion failures. No live
model or public board was used. `final-os-isolation.log` records unavailable
UID/GID separation (77), not a pass.

The robot and untested-module ratchet outputs are identical before/after. Finite
guards have zero new findings. The claims ledger adds five paired claims but
retains the previous 12 unpaired, 1,558 untagged and unsigned-ceiling-raise debt.

The unprefixed and initial logs are development history. In particular the first
scope mutation produced an unrelated KeyError and does not count as a valid
control. Its corrected final run fails with the intended assertion. Initial
finite output records two count-query heuristic findings removed by changing
the query, without editing the baseline.

Patch logs and `archive-validation.json` record clean application and byte
comparisons. The root SHA256SUMS.json covers packaged files except itself.
Reports, historical notices and evidence are added after the source test run.
The copied run_validation.py records the orchestration used in the review
workspace; its WORK-relative extraction layout is not an installed repo command.
Use the documented repository commands to reproduce individual checks.
