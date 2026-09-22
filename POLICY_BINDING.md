# Current artifact channel review — 21 September 2026

Read **ARTIFACT_CHANNEL_REVIEW.md**, **ARTIFACT_CHANNEL.md** and
**GROK_COMPARISON_REVIEW.md** for the current change and measured limits.
Official wrapper: **4,934 passing checks / 137 files; seven failed
files; exit 1**. The previous release reproduces the same seven
environment-blocked failures. New artifact tests **31/31**, new removal
controls **6/6**. OS separation remains unavailable (77), and three
existing repository ratchets still fail. No live model run is claimed.
The report below is historical. The incremental patch is
`artifact-channel.patch`; `authority-repair.patch` remains cumulative.

---

# Current agent boundary review — 21 September 2026

Read **AGENT_BOUNDARY_REVIEW.md**, **GOVERNANCE_OBSERVABILITY.md** and
**agent/README.md** for the new server response boundary, standalone
agent client, deployment guidance and proposed visibility experiment.
Current source: **4,903 passing checks / 136 files; seven socket-related
failed files; exit 1**. New tests: **18/18**; new removal controls: **4/4**.
OS isolation remains unavailable here (77). No live-model result is claimed.
The report below records earlier work and historical measurements.
`authority-repair.patch` is cumulative; `agent-boundary.patch` is the new
incremental patch. See the current report for exact baselines.

---

# Policy artifact binding — 21 September 2026

An execution grant now identifies the operator policy artifact under which it was issued. The privileged broker checks that identity against its own construction-time snapshot before reserving the grant's nonce. An old grant cannot be used on a broker configured for a different snapshot, even if the action, subject, signing key and capability scope still match.

This is a provenance and stale-authorization check. Existing effect, destination, scope, human approval, halt, envelope and replay checks still determine whether an action may execute.

## Configuration and issuance

1. Authenticate the deployment configuration outside the agent process. For signed JSON, use the existing `signed_config.load_verified` with a broker-controlled key. A `PolicySnapshot` alone does not authenticate its source.
2. Construct a snapshot from that verified document. Configure policy consumers from this same detached document. Include the actual policy data and explicit versions/content digests of external rule implementations. Include no keys, access tokens or other secrets.
3. Supply the snapshot to `ProductionActuationBroker(..., policy_snapshot=snapshot, ...)` along with its existing required human approval, halt, evidence and isolation configuration.
4. The trusted grant issuer uses `Grant.issue(..., policy_hash=snapshot.policy_hash, ...)`. Obtain this expectation from deployment state, not from an agent's proposed grant or request.
5. Archive `snapshot.to_dict()` with the deployment. The digest is public metadata, not a credential.

```python
from driftcore.verification.policy_snapshot import PolicySnapshot
from driftcore.verification.signed_config import load_verified

# Run in trusted deployment bootstrap. These variables are operator inputs.
snapshot = PolicySnapshot(load_verified(policy_path, config_verification_key))
policy_document = snapshot.to_dict()

# Construct the broker's rules from policy_document; pass snapshot to the broker.
# The trusted issuer includes snapshot.policy_hash in each Grant.issue call.
```

The example deliberately omits a universal deployment factory: DriftCore has separate policy consumers, rather than a single JSON policy language. `test_policy_binding.py` contains a runnable example in which the same snapshot supplies the egress allowlist and actuator capability requirements. Its test keys are public fixtures.

## Wire and compatibility contract

- `Grant.policy_hash` is optional for legacy development users. When present it is a lowercase 64-character SHA-256 digest included in the HMAC payload and preserved by `to_dict`/`from_dict`.
- A verifier presented with a bound grant requires `expected_policy_hash`. A verifier with an expectation refuses unbound grants. Missing, malformed and mismatched bindings fail closed.
- The broker supplies the expectation from its own pinned snapshot. `policy_hash`, `expected_policy_hash`, `policy_snapshot` and equivalent context fields supplied in an execute request cannot replace it.
- `ProductionActuationBroker` now requires a `PolicySnapshot`. Existing production bootstraps and grant issuers need updating. There is no production compatibility switch accepting old unbound grants.
- Development `ActuationBroker` still permits legacy unbound grants when configured without a snapshot. Its disabled-layer report identifies the missing binding. It rejects bound grants when no policy expectation is installed, rather than ignoring their meaning.
- Legacy grants retain their previous serialized payload and signature when `policy_hash` is absent. A bound grant fails signature verification if its hash is altered, removed or replaced with null.
- A policy refusal precedes nonce reservation and spending. A matching grant still goes through all the existing gates and single-use handling.
- Broker records and durable INTENT/COMPLETION entries identify the broker's expected `policy_hash`. These remain the existing hash-chained evidence records; this change does not introduce independently signed execution receipts or prove a physical effect occurred.

## Snapshot identity

`PolicySnapshot` stores canonical UTF-8 JSON bytes, detached from its input. Editing a nested input or a returned `to_dict()` value does not alter it. Inputs must be nonempty dictionaries composed of built-in JSON types with string object keys and finite numbers. Cycles and unsupported values are rejected.

The digest is SHA-256 over `b"driftcore-policy-snapshot-v1\x00" + canonical_bytes`. Encoding uses Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`. Object key order is ignored; list order and numeric representation are significant. This is a versioned Python encoding, **not RFC 8785** or a cross-language canonicalization standard. A non-Python issuer must reproduce these exact bytes or use an archived digest from trusted deployment metadata.

## Rotation and limits

There is no mutable global policy expectation and no RPC for changing it. To change policy, stop/drain the old broker, deploy the new snapshot and rules, then issue fresh grants. An old broker still accepts its own policy version until stopped or otherwise revoked. Policy binding alone is not immediate fleet-wide revocation. Use a fresh revision field when returning to previously used rule content if previously issued, unspent grants must remain invalid.

The hash covers the supplied JSON artifact. It does **not** automatically discover every callback, live registry, dependency, credential, binary, physical setting or external service state. An operator who changes those while reusing an inaccurate manifest defeats that provenance claim. Such changes require disciplined rollout, versioned artifacts and deployment checks. Existing dynamic safety checks remain necessary. Automatic attestation that every live rule matches the manifest is future work.

An adversary with arbitrary execution in the privileged broker can patch Python objects or read symmetric keys. Frozen objects, private attributes and read-only properties do not create OS isolation. Separate identities, credential custody and complete mediation remain deployment requirements.

Claude's unfinished `TargetGrant` implementation was not available in this input. This patch extends the actual `signed_permission.Grant` and `mediated_actuation` path present in the supplied repaired repository. It does not claim to merge unseen code or cover every other authorization primitive in DriftCore.

## Tests and evidence

`python3 test_policy_binding.py` runs 22 tests, including real `_handle` execution with a recording actuator. It covers canonicalization, mutation isolation, wire round trips, valid-signature stale policies, signature tampering, downgrade/missing-policy cases, ignored request overrides, nonce preservation, action/destination checks, replay, evidence and production configuration.

`python3 scripts/check_policy_binding_controls.py NEW_OUTPUT_DIRECTORY` removes four protections independently in temporary source copies. Each selected test must pass before removal, fail by assertion after removal and pass after restoration. Import failures and crashes do not count as detections.

The rotation probe under `verification/field-review/` applies policy B to the broker and presents authorization issued under A. The old API has no policy binding and records one effect; the new API rejects the stale policy and records zero. The action itself is allowed by both policies. This demonstrates missing policy provenance in the old API, not that its original destination check permitted a forbidden destination.

The final source suite reports 4,885 passing checks across 135 files, seven restricted-socket failures and exit 1. See `FIELD_REVIEW.md` for all results and the remaining gates. These local tests do not establish isolation against a hostile operating-system process.
