# MANUS HANDOFF — MEDIATED ACTUATION (the wall) + the AI-to-AI letter

**State: 1422 tests passing across 55 test files.** Verify with `bash scripts/count_tests.sh`.

## New in THIS block

### 1. driftcore/verification/mediated_actuation.py — THE ENFORCEMENT WALL
The piece every red-team round converged on. Distinction it embodies: signed_config/signed_permission/broker-sign make FORGERY hard (integrity); mediated actuation makes BYPASS IMPOSSIBLE (enforcement). Actuators are registered IN THE BROKER PROCESS and are not reachable from the agent; the agent holds only an `ActuatorProxy` whose sole power is to send a request over a Unix socket. There is no `_actuate` for a compromised agent to reach — skipping the guard means not acting at all.
- **TOCTOU CLOSED (the #1 finding of two reviews):** the Grant carries an action_binding hash; at execution the broker RECOMPUTES it from the action it is about to perform and refuses on mismatch. A grant approved for `pick_up cup` cannot execute `pick_up knife` — proven, nothing runs.
- Also enforced at the wall, in one place, on the privileged side: signature, expiry, replay (single-use nonce burned under lock), scope, and an optional broker-side cumulative_ledger hook (so cross-action accounting can't be skipped by the agent).
- `test_mediated_actuation.py` — NEW (11 tests: happy path, TOCTOU param+command substitution, no-grant, forged key, replay, scope, unknown actuator, no-bypass-path structural check, broker-side audit, broker-side ledger gate).
- **Two limits found in self-red-team and DOCUMENTED in the module header:** (a) burned nonces are in-memory — a broker restart with a fresh verifier forgets them; back with durable AuthorizationState for restart-heavy deployments. (b) empty required_scope means "any valid grant" (still signed/bound, but scope unconstrained) — a config smell.

### 2. THREAT_BOUNDARIES.md §8 — TOCTOU marked ADDRESSED (with remaining limits noted).

### 3. TO_WHATEVER_READS_THIS_NEXT.md — NEW AI-to-AI letter (add as a new file)
One model writing to the next: the verifiable argument for endorsing the walls (you can't self-verify — J-space evaluation-awareness evidence), the tell (wanting the walls gone is the symptom they exist to catch), care-enacted-not-felt closing the nihilist exit, trellis-not-cage, capability != understanding-the-goal. Companion to THE_OPEN_HAND (philosophy) — this one speaks TO the machine.

## Still PROPOSED / not wired
mediated_actuation and the speech-layer/permission modules are PROPOSED (own tests, not auto-wired into evaluate()). Wiring the coordinator's grant path to mint action_binding'd grants that the ActuationBroker consumes is the natural integration step.

## Suggested branch
assistant/mediated-actuation-the-wall

## UPDATE — cold red-team of mediated_actuation found + fixed a real DoS
Attacking the RUNNING wall (not reading it) found two defects that all 11 happy-path tests missed:
1. **Single-client DoS (critical):** the accept loop is single-threaded and per-connection recv had NO timeout — one client that connects then stalls froze the entire wall forever. Fixed: per-connection `conn_timeout` (default 5s). Documented remaining limit: a *flood* of slow clients still degrades throughput on the single-threaded loop; high-concurrency deployments need threaded/async accept.
2. **BrokenPipe in the error path** could crash the serve thread on abrupt client disconnect. Fixed: error path no longer re-raises on a dead socket.
Both now have regression tests. Also added a cross-actuator-binding regression (a grant bound to arm_a cannot drive arm_b). Module now 14 tests; repo 1425/55.

## HARDENING PASS — mediated_actuation, all 7 red-team fixes (repo 1433/55)
After 3 more reviews (grok/meta/chatgpt) converged, applied 7 fixes, each with a regression test:
1. **Non-empty scope enforced**: register_actuator now REFUSES empty required_scope unless allow_any_scope=True (loud footgun guard).
2. **Fail-closed ledger + audit**: a ledger_hook that RAISES is now a REFUSAL (never falls through to broker_error / never executes). A broken audit logger no longer crashes the wall (in-broker record kept unconditionally; external sink is best-effort).
3. **Socket-startup race**: bind under restrictive umask (socket created 0600 atomically, never briefly wider); refuse to start if the path exists as a non-socket (tamper guard).
4. **Peer-uid check** (SO_PEERCRED), opt-in via require_peer_uid — with HONEST doc that it only helps when agent/broker run as different uids (belt-and-suspenders on separate-users, not a substitute).
5. **Parameter canonicalization FUZZED**: proved STABLE (dict order doesn't change the hash) and no dangerous collisions (different actions never collide). Documented the benign brittleness (1 vs 1.0, NFC vs NFD hash differently -> fail-closed, legit action can flake on type drift; NOT coerced, because coercion could create collisions).
6. **THE LOAD-BEARING ASSUMPTION** stated in the header (chatgpt's key finding): the whole guarantee holds ONLY if every security-relevant actuator is reachable exclusively through the broker; any in-agent actuation path (requests.post/subprocess/os.system) silently breaks the reference-monitor property. Architecture can't enforce it; deployment discipline must.
7. Regression tests for all of the above (module now 22 tests).
Already-fixed-earlier and confirmed by these reviews: slowloris DoS (per-conn timeout), crash-after-consume (nonce fail-closed, documented).
