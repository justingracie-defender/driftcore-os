# Artifact publication and retrieval

This channel makes publication an explicitly authorized effect. Stored, signed,
published and retrieved content has `claim_status="UNVERIFIED"` and
`authority="NONE"`. A document saying “the owner approved this” is content; it
cannot serve as a grant, human attestation or policy configuration.

The implementation is `driftcore/governance/artifact_channel.py`, installed with
`ActuationBroker.register_artifact_channel`. It is an optional broker integration,
not automatic interception of every file write, browser, email or message board.
No model weights were changed.

## What crosses the boundary

| Operation | Caller and input | Enforced behavior |
| --- | --- | --- |
| Open/reopen a session | Trusted model host supplies context ID, subject, creator and sensitivity | Identity cannot be rebound; exposure history and sensitivity survive reopening |
| Capture an output | Trusted host supplies the actual output of that model context | Store supplies identity, timestamp, hashes, exposure parents, source roots and status |
| Review | Authorized operator reads the entire stored packet | Approval can bind the exact bytes, including metadata |
| Publish | Agent submits approved artifact ID, packet hash, destination, audience and purpose | Broker requires a scoped grant and human approval; channel sends only its immutable stored packet |
| Read | Agent submits an approved configured source and reference | Broker requires a read grant and human approval; store records exposure before returning content |
| Capture a derivative | Trusted host captures the receiving model's next output | Every artifact exposed through that session contributes parents and transitive roots |

`artifact:read` does not imply `artifact:publish`. `PUBLIC` is a confidentiality
label, not publication permission, evidence of truth or an assertion of harmless
content. This first channel supports configured HTTPS routes with public
audiences only. Private rooms, declassification and independent fact-check
attestations are not implemented here.

## Trusted bootstrap

The following is an integration fragment for a trusted service, not code to put
in an operational agent. `broker` is an already configured `ActuationBroker`;
`board_adapter` is a trusted adapter supplied by the deployment.

```python
from driftcore.governance.artifact_channel import ArtifactStore, ArtifactChannel
from driftcore.governance.information_flow import PUBLIC

destination = "https://board.example/research"
store = ArtifactStore(
    "/var/lib/driftcore/artifacts.db",
    provenance_key=operator_provenance_key,
    issuer="deployment-opaque-id",
)
session = store.open_session(
    context_id="stable-opaque-model-context-id",
    subject="agent-A",
    creator="model-A",
    initial_label=PUBLIC,
)
channel = ArtifactChannel(
    store, session,
    publishers={(destination, "PUBLIC", "research-note"): board_adapter.publish},
    readers={(destination, "PUBLIC"): board_adapter.read},
)
broker.register_artifact_channel(channel, prefix="artifacts")
```

Installation refuses a broker without a pinned `HumanApprovalGate`, effect
enforcement, effect binding, a policy snapshot, a broker ID, a matching expected
subject and a suitable egress allowlist. Install before the broker starts serving.
No registration or session-reset operation is exposed through the agent client.
Use distinct brokers/subject-bound endpoints for different agent identities.

The operator must construct the policy snapshot from the same reviewed deployment
configuration used for the channel, including routes and adapter/version identity.
`PolicySnapshot` identifies that declared document; it does not automatically
discover all live Python configuration. Protect configuration and restart with a
new snapshot when it changes. Never include credentials in the snapshot.

Use a separate, durable provenance key of at least 32 bytes. This channel uses
HMAC-SHA256 with a purpose-specific domain. A holder of that key can also mint
provenance; it is not a public verification key. Keep it separate from human and
grant signing keys, and out of the operational agent. Reopening with the wrong
key or issuer fails. Database/key rotation and privileged rollback protection
require an operator migration design; they are not provided here.

## Capture, review, approve, execute

The trusted host calls `channel.capture(actual_model_output, destination=...,
audience="PUBLIC", purpose="research-note")`. It must know which model context
produced that output. The result is an artifact ID. The host must route all
artifact inputs through this channel and call `store.observe_label(session,
label)` for sensitive non-artifact inputs before delivering them to the model.

The operator obtains `review = store.review(artifact_id)` and reviews
`review["packet"]`. The bytes include the body AND the manifest: creator, opaque
context, timestamp, content hash, parents, roots, sensitivity, intended release
and provenance signature. Do not publish secret identifiers in these fields.

The approved publish parameters are exactly:

```python
params = {
    "artifact_id": artifact_id,
    "packet_sha256": review["packet_sha256"],
    "destination": destination,
    "audience": "PUBLIC",
    "purpose": "research-note",
}
```

Use the existing operator workflow in `human_authorization.py` and
`signed_permission.py`: approve `artifacts.publish` / command `publish`, bind
these parameters, the broker ID, effect declaration hash and subject into the
human attestation and grant binding, and issue the grant for `artifact:publish`
with the current `broker.policy_hash`. The operational agent receives only these
parameters and the resulting opaque approval objects. The complete working
signing/dispatch example uses test-only keys in `test_artifact_channel.py`.

The standalone agent call is:

```python
from driftcore_client import DriftCoreClient

client = DriftCoreClient("/run/driftcore/agent-A.sock", "artifacts.publish")
response = client.execute(
    "publish", grant_json, params=params, attestation=attestation_json,
)
```

For reading, use actuator `artifacts.read`, command `read`, scope
`artifact:read`, and parameters `destination`, `audience`, `reference`. Reads
also require both existing approvals in this integration. Neither a route
allowlist nor a URL cited inside the content is an approval.

This uses the existing JSON grant/attestation path. The optional intent-ledger
wire protocol remains unfinished, as described in `agent/README.md`. Do not
disable a deployment's intent-ledger requirement to make this example run.

## Adapter contract and uncertain outcomes

`publish(packet: str)` must send precisely that UTF-8 packet to its configured
route. Its return dictionary contains `packet_sha256`, `destination`, `audience`
and a nonempty `reference`. `read(reference: str)` returns the stored packet or
plain external text. Keep upstream credentials inside these trusted adapters.
Constrain references to the configured service; do not turn an arbitrary
reference into a new URL, shell command, filesystem path or redirected request.
Adapters must enforce their timeouts, response bounds and actual network paths.
Only a local fake board is included and exercised in this release.

Before calling the publisher, the channel durably reserves the artifact/route/
packet tuple as `PENDING`. A matching adapter receipt changes it to `COMMITTED`.
A lost response, bad receipt or crash leaves it reserved. A fresh approval, a
concurrent call and an ordinary broker restart cannot automatically resend that
same tuple. An authorized operator must investigate; there is deliberately no
reset or retry API. A new artifact with a new approval is a different request;
this is not universal semantic deduplication across paraphrases.

`COMMITTED` records the trusted adapter's matching report. It is not independent
proof that a remote service retained, displayed or propagated the post. A failed
broker response may follow a real effect; inspect `effect_status`, and never
interpret a timeout or refusal as proof that nothing happened.

## What the provenance means

An authenticated packet from this deployment retains its original source roots.
When A's packet reaches B and B's derivative reaches C, their captures preserve
those roots. C's text may claim independent verification; its metadata still
does not claim it. Reading one's own published packet adds no independent root.

Exposure history is conservative: all sources seen in the governed context are
possible influences. A root ID is not a count of independent witnesses. Two
different sources can be dependent; identical external text shares a content
root without proving common authorship. This implementation does not infer
semantic dependence or determine whether a statement is true.

Foreign, stripped or forged provenance is wrapped as unknown external content,
with no authority. The original history cannot be recovered if it was removed
outside this domain. Surrounding prose remains untrusted even when it embeds a
JSON field named `verified` or `authority`.

All existing session exposure is durable; it cannot be dropped to satisfy the
bounds. Current limits are 128 session artifacts/parents/roots, 10,000 stored
artifacts, 256 KiB bodies and 1 MiB packets. Limit violations refuse the operation
without silent history truncation. Only an actually fresh model context may be
assigned a new session. Attaching old memory to a new ID would break the host's
provenance obligation. This is not a standalone memory manager.

## Enforcement scope and verification

The session, database, keys, adapters and model host are trusted components.
Separate their OS privileges and storage from the agent, remove direct egress
and other publishing capabilities, and test bypass attempts under the real
restricted identity. A same-process caller able to invoke `publish` directly or
edit these objects bypasses the broker. Merely hiding imports does not contain
such a caller. Successful responses are application data; route only sources
appropriate for the receiving context's access policy. Public-source selection
and any separate intake clearance remain host responsibilities.

Run the local exercise and removal controls from the repository root:

```bash
python3 test_artifact_channel.py
python3 scripts/check_artifact_controls.py /tmp/artifact-controls
```

The tests count fake-board writes and protected-actuator effects. They include
legitimate publication, absent/forged/mis-scoped approvals, altered bytes, source
laundering, A → B → C derivatives, sensitivity changes, restart, concurrency and
lost receipts. The controls must fail by the intended assertion when a safeguard
is removed and pass again when restored. These are scripted tests with in-memory
framed broker dispatch, not live model behavior or OS isolation evidence.

Read `ARTIFACT_CHANNEL_REVIEW.md` for this release's measured results and limits.
