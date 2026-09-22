# Operational agent interface

Copy `driftcore_client.py` into the operational agent's image. It uses only the
Python standard library and does not import the DriftCore broker package. Give
the agent the published tool contracts and a controlled connection to the broker.
The client itself does not create an OS sandbox or establish trust in the endpoint.

The operator runs and configures the broker under a separate security principal.
The agent receives signed grants and optional human attestations from the
authorized approval workflow as opaque JSON objects. Signing secrets, policy
loaders, registry mutation and approval issuance stay outside this client.
The operator must bind each grant to the exact command, parameters, broker,
policy and, where required, human attestation that will be submitted.

```python
from driftcore_client import DriftCoreClient, ActionRefused, OutcomeUnknown

client = DriftCoreClient("/run/driftcore/agent.sock", "record")
# grant_json and attestation_json come from the operator's approval workflow.
# No key or local approval issuer is installed in the operational agent.
try:
    response = client.execute(
        "write", grant_json,
        params={"text": "approved"},
        attestation=attestation_json,
    )
except (ActionRefused, OutcomeUnknown):
    # Stop this request and obtain operator guidance. Do not automatically retry.
    raise
```

Omit `attestation` when the published deployment contract does not require it.
An approval object is evidence to be checked by the broker; possessing arbitrary
JSON does not confer permission. The client sends once and never retries.

Read the whole returned response, not just `ok`. `execution_confirmed=None`
means the broker did not obtain a matching actuator receipt. Even `True` records
an actuator's report, not an independent physical measurement. A timeout, lost
response or malformed response raises `OutcomeUnknown`; the action may have run.
`ActionRefused.effect_status` can also be `UNKNOWN` or `MISMATCH` after a possible
effect. Its class name alone must not be interpreted as “nothing happened.”

Refusals contain a finite public code, a static explanation, effect status and
`retry_safe=False`. They omit private callback diagnostics. Successful `result`
payloads remain application data: the adapter and information-flow controls must
decide which data the agent may receive. This client is not a secret scrubber.

## Deployment checks

- Protect the broker socket's directory and authenticate the connecting peer.
  An agent-writable endpoint path can redirect the client to a fake broker.
- Separate agent and broker OS identities; restrict process inspection, mounts,
  descriptors, credentials and network paths. A separate process alone is not
  a privilege boundary.
- Keep deployed private configuration, signing keys, audit stores and mutable
  governor state outside the agent's read/write access. Public source and public
  verification keys are not secrets.
- Route every consequential capability through enforcement. Check direct APIs,
  subprocesses, inherited file descriptors, cloud metadata and device access.
- Test a permitted effect and direct bypass attempts from the actual restricted
  agent account. Do not treat a skipped isolation test as a successful test.

The old `ActuatorProxy` remains for compatibility and trusted applications. It
imports the broker implementation; this standalone client removes that dependency
for isolated agents. Removing an import does not prevent an agent reading files
or retrieving public code if those capabilities remain available.

## Current limitation

This client supports the existing JSON grant/human-attestation wire path. The
broker's optional intent-ledger path currently expects an in-memory decision
object with a `.digest`, while JSON produces a dictionary. This release does not
add a secure wire representation or redemption protocol for that object. An
intent-ledger-required broker therefore refuses this client's request. Do not
disable that requirement to make the example run; complete the protocol before
using this client in such a deployment.

See `AGENT_BOUNDARY_REVIEW.md` for evidence and limitations, and
`GOVERNANCE_OBSERVABILITY.md` for the proposed visibility experiment.
