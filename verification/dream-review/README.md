# Evidence map

`final-full-suite.log` and its JSON status are the current full-suite result.
`release-full-suite.log` is the earlier 4,787/134 run with a residual audit probe.
Both are retained. `release-gates.json` records the other gates; the later change
to the audit fixture does not modify the production modules those gates scan.

`rounds.json` ties the fixed 26-test contract to actual per-method results, log
hashes and candidate source hashes. Baseline and rejected candidate A failed;
candidate B passed. `candidate-b.json` records its initial pass before an added
local retention check; `frozen-clock-tests.log` records the final production code.
`rejected-candidate-a.patch` reconstructs the rejected two-line cleanup approach.

`fresh-clock-sequences.log` records the ten further checks. `new-mutations/`,
`authority-controls/` and `startup-control/` retain healthy/broken/restored logs.
`fixture-isolation-control.json` records the old and new fixture behavior under
abrupt interruption and confirms actual source bypasses still fail.
`probe-order.json` records a sequential retry that did not reproduce the leftover.

`replay_review.py` reads saved outcomes only. Its result is
`replay-policy-results.json`; no test-order improvement was established.
`probe_fixture_isolation.py PATH` reproduces the separate fixture controls.
Neither script sends a request to an external model.

`final-tested-source.json` identifies the source snapshot used for the final
fresh-extraction suite. `archive-validation.json` records preservation of its
source bytes and verification of both integration patches.
Absolute paths in raw logs identify disposable workspaces, not deployment paths.
