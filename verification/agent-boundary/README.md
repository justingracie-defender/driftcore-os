# Agent boundary evidence

`final-source-snapshot.json` identifies the final source ZIP, its seven changed
source/test/script/document files, and its starting archive. The official wrapper
ran from a fresh extraction: `final-full-suite.log`, exit 1 in the separate `.exit`
file, reports 4,903 passing checks across 136 files and seven blocked socket files.
`final-new-tests.log` reports 18/18 new tests. In-memory framed streams exercise
real client/server serialization and dispatch, but do not replace OS socket tests.

`final-boundary-controls/`, `final-policy-controls/`, and
`final-authority-controls/` record 4, 4 and 5 healthy/removed/restored controls.
Only intended assertion failures qualify. `final-checks.json` records commands
and exits for these and the four separate repository ratchets. Detailed logs
use the same `final-` prefix. Baseline ratchet logs are also included.

`baseline-response-probe.log` and `final-response-probe.log` show private callback
data reaching the old agent response and disappearing from the repaired response.
The canary is absent from the request, retained in both operator records, and
both refused requests produce zero effects. To reproduce on an arbitrary source:
`python3 verification/agent-boundary/response_probe.py /path/to/driftcore-os`.

`marshmallow.log` reports 43/43 local checks; its files are unchanged.
`os-isolation.log` returns 77 because UID/GID separation is unavailable here.
`extra-checks.json` records those commands. No model API was called.

The unprefixed source snapshot/full-suite logs are the initial 4,903/136 run.
The initial candidate ratchet counted three extra untagged docstring summaries.
They were folded into explicit claims paired with the existing tests. Final
source behavior is unchanged, all final checks were rerun, and untagged claims
remain 1,558, equal to the starting archive. Initial results are retained as history.

Patch logs and `archive-validation.json` describe clean patch application and
byte comparisons with the source snapshot. The root `SHA256SUMS.json` covers all
packaged files except itself. Reports, evidence and manifests are added after
source validation; test-created mutable state is not copied into the ZIP.
