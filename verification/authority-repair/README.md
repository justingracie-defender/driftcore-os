# Verification evidence for the September 13 merge

Start with `AUTHORITY_REPAIR.md` at the project root. This directory retains
failed runs as well as successful ones. Earlier totals must not be substituted
for the final result.

- `release-runs.json` and `release-*.log`: final source snapshot extracted fresh,
  including the official **4,827 / 132, seven failed files, exit 1** result.
  The two `release-*-mutation/` directories contain healthy, broken and restored
  runs for the five authority controls and one SQLite control.
- `archive-validation.json`: input and tested-source hashes, unchanged-source
  comparison, preservation of the newer Marshmallow code, and patch result.
  `patch-application.log` records application to a fresh September 13 extraction.
- `incoming-*`: the unmodified September 13 baseline (4,796 / 130, exit 1).
- `merged-full-suite.log`: first merged run (4,735 / 131, exit 1), before the
  SQLite startup repair; it exposes the two additional nonce-store failures.
- `final-full-suite.log`: an intermediate SQLite repair with seven tests
  (4,825 / 132, exit 1). The final version adds two compatibility tests and is
  recorded in `release-full-suite.log` (4,827 / 132).
- `nonce-startup-unsynchronized.json`: original input and pre-fix merge both
  reproduce the WAL startup lock error. `nonce-startup-probe.json` also preserves
  the earlier synchronized run that did not reproduce it.
- `sqlite-final-checks.json`, `sqlite-startup-final.log`, `merged-finite-guards.log`
  and `merged-claims-ledger.log`: latest focused SQLite tests and affected gates.
- `checks.json` and `ratchets.json`: earlier focused command statuses and baseline
  comparisons. The later SQLite-specific results above supersede their finite
  guard and claims-ledger measurements. Unaffected audience, broker-surface,
  untested-module and OS checks were not rerun just to refresh a timestamp.
- `probe_pinned_authority.py`: reproducible 7-check coordinator follow-up. From
  the project root run `python3 verification/authority-repair/probe_pinned_authority.py .`.
- `probe_nonce_startup.py`: retained concurrency reproducer. The regression test
  `test_nonce_store_startup.py` is the maintained, bounded verification gate.

Absolute paths in raw logs identify the disposable copies used for each run.
No log claims successful Unix-socket or OS-identity isolation in this environment.
