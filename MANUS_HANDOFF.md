# MANUS HANDOFF — v4.5.0 hardening block (post red-team rounds 1–3)

**State: 1275 tests passing across 49 test files.** Run `bash scripts/count_tests.sh` to verify before committing.

## New in THIS block
- `driftcore/verification/signed_config.py` — NEW: tamper-evident config loading (HMAC-signed; refuses unsigned/altered config; callable key for keyring; detached mode). Defense-in-depth; in-memory-key limit documented.
- `driftcore/verification/broker_process.py` — NEW: the reference-monitor's first brick. Signing key lives in a SEPARATE process; agent verifies/requests-sign over a Unix socket and never holds the key. key_id allowlist + timestamp/TTL replay defense baked in. Ceiling documented (signing != enforcement).
- `driftcore/verification/cumulative_ledger.py` — NEW: cross-action accounting. Per-(owner,window) running budgets for egress volume (count + bytes), cumulative verifier-sourced harm, and per-effect caps. Closes fragmentation / cumulative-harm / slow-exfil (the gap four red-team rounds converged on). Durable, hash-chained, cross-instance, tamper-evident.
- `SPEECH_LAYER_CONTENT_GOVERNANCE.md` — NEW design doc: two-axis content model (topic ceiling vs harm floor), three modes, crisis override (§3a: care may tighten, never loosen).
- `SPEECH_LAYER_OUTPUT_BACKSTOP.md` — NEW design doc: buffer->classify->release backstop; rolling context; regenerate-or-refuse; classifier-as-evidence-not-judge; enforceable deployment gate; production-hardening section; adopt-don't-build the classifier.

## New test files
- `test_signed_config.py` (12), `test_broker_process.py` (12), `test_cumulative_ledger.py` (23)

## Still PROPOSED / not wired (do not "fix")
- signed_config / broker / cumulative_ledger are PROPOSED modules with their own tests; NOT yet wired into the coordinator's evaluate() path. Wiring each is a separate, deliberate change (each needs a fail-closed policy decision).
- calibration.py, consequence_projection.py still unwired.
- Version strings still 4.1.x — flip with status language after Justin's red-team passes.
- No CI config yet. Consider adding logs/ data/ *.jsonl spent-token files to .gitignore (repo carries runtime state).

## Suggested branch
assistant/v4.5.0-hardening-block-2
