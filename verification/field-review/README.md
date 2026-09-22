# Evidence for the policy artifact review

`final-full-suite.log` and `.exit` report the current 4,885/135 run and exit 1.
Seven socket-dependent files are unavailable in this environment.
`final-source-snapshot.json` identifies the exact source archive and seven changed
source/test/script files. The new root test file contributes 22 checks.

`full-suite.log` is the earlier 4,884/135 run with 21 new checks.
`source-snapshot.json` identifies that earlier source. Both remain as history.

`policy-controls-final/` contains the four valid healthy/removed/restored controls.
`policy-controls/` retains the first attempt, including the invalid serializer
control that failed with errors. Errors were not counted as successful controls;
the replacement isolates signing from wire serialization and policy comparison.
`authority-controls/` contains the five earlier protection-removal controls.

`baseline-rotation.json` and `stage-rotation.json` record actual effect counts of
one and zero. Re-run the local probe with an absolute repository path:
`python3 verification/field-review/policy_rotation_probe.py /path/to/driftcore-os`.
The action is allowed by both policies; the missing property is policy provenance.

`ratchets.json` records separate commands, exit statuses and result tails for the
previous source and final candidate. Individual logs contain their full output.
`extra-checks.json`, `marshmallow.log` and `os-isolation.log` record 43 passing local
marshmallow checks and the unavailable OS-isolation check (77), respectively.

Patch logs and `archive-validation.json` record clean application to the exact
matching baselines and byte comparisons. `SHA256SUMS.json` at the repository root
covers every packaged file except itself. No model API was called in this review.
