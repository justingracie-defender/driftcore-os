# Review of Grok's unfinished comparison — 21 September 2026

The comparison is useful as a list of engineering questions. Its ratings are not
independent evidence that DriftCore or another system enforces a property.
This review reads the supplied app's data; it does not claim to have built or
completed Grok's application or run the other projects' suites.

Input: `grok-workspace.zip`, SHA-256
`a1c90df6f55f3d9905a02f4c3e032d71537e704c39e029f51d9ec2e114fe5dad`.
The substantive comparison is `src/lib/matrix-data.ts`. Its nested
`attachments/driftcore_full_2026-09-13.zip` has SHA-256
`328a7ffd64035f27779a84362c68ab5e68f36c2a4ed6ebb6420324dea2f045b6`.
That is the older base, not the cumulative September 21 tree used for this patch.
Do not overwrite later authority, policy or agent-boundary repairs with it.

## What we can use now

| Lesson | Primary-source check or local evidence | DriftCore application |
| --- | --- | --- |
| Carry security state across calls | CPEX describes marking a session sensitive after a read and checking that state on later egress | Artifact sessions persist exposure and sensitivity; capture cannot supply a shorter parent list |
| Separate untrusted information from authority | CaMeL extracts control/data flow from trusted input and checks capabilities at tool calls | Retrieved artifacts remain data; the broker still requires its own human approval and execution grant |
| State the deployment boundary | AGT explicitly describes shared-process middleware and recommends separate containers for production isolation | Keep the artifact host, store, credentials and broker outside agent privileges; local fake streams do not prove this boundary |
| Observe the consequence | The app asks whether a check actually controlled the effect | Count board writes, preserve uncertain outcomes, and remove safeguards to show the tests depend on them |

The CPEX behavior above is documented in its
[project README](https://github.com/contextforge-org/cpex). This supports the
design comparison, not a claim that we have independently tested its deployment.

The CaMeL authors report 77% task completion with their security property versus
84% for the undefended system in AgentDojo. That supports measuring legitimate
utility alongside blocked attacks. Our channel does not implement CaMeL's
interpreter or inherit its theorem.
[CaMeL v2](https://arxiv.org/abs/2503.18813v2).

AGT's own security section distinguishes its application middleware boundary
from OS isolation. Its automated test counts remain project-reported counts;
they are not, by themselves, an independent audit.
[AGT security section](https://github.com/microsoft/agent-governance-toolkit#security).

SINT and Vouch are further research leads. This pass does not confirm their
individual hardware, cryptographic or conformance claims and does not import
those claims into DriftCore's safety case.

## Corrections and directions for Grok

1. **Add evidence to each cell.** `Cell` currently has coverage, evidence kind,
   note and optional limit, but no source URL, commit, section, observation date
   or test command. The file has only six project-level links. Add an evidence
   list with those fields and a clear author-reported versus independently-run
   distinction. Pin the exact DriftCore archive for every local result.

2. **Make “enforced” conditional on actual evidence.** The legend requires tests
   or a public evaluation, yet several cells use `coverage: "enforced"` with
   `evidence: "docs"`. Show “documented” until a linked test demonstrates the
   relevant effect and states its threat model. Apply this to every system.

3. **Separate unknown, absent and out of scope.** A missing public claim is not
   proof that a feature is absent. A robotics requirement outside a software
   project's scope should not count as a failed security property.

4. **Separate authorship from evidence format.** A paper or large test suite can
   still be authored by the project itself. The “independent evaluation” row
   cannot be established by organization size, repository ownership or count of
   tests. Name who ran it, which version, the command and the resulting artifact.

5. **Avoid a single strength score.** `categoryScore` averages numbers assigned
   to coverage labels. That is a display heuristic, not a calibrated security
   measurement. Keep it explicitly labeled or replace it with distributions;
   filter by common threat model before comparing systems. Do not rank overall
   safety from this arithmetic.

6. **Split the provenance row.** Model/build identity, sensor authenticity,
   artifact lineage, claim verification and authorization are different things.
   A signed model hash does not verify a sentence. This release implements one
   bounded artifact channel, not hardware-rooted model or sensor attestation.

7. **Separate receipts from observed effects.** A signed receipt proves who
   signed specified bytes under an assumed key binding. It can still report an
   incorrect consequence. Record the adapter result, uncertain state and any
   independent observation separately. A refusal following a write is not a
   prevented write.

8. **Do not substitute related controls for revocation.** A halt flag or spent
   nonce is not evidence of targeted credential revocation. Test an unspent,
   unexpired grant after explicit revocation and define restart/disconnection
   behavior before marking that property demonstrated.

9. **Distinguish signed configuration from access control.** The matrix's
   rationale that unsigned allowlists get rewritten is too broad. Protected
   configuration can be authoritative without a portable signature; signed
   configuration still requires a trusted issuer and a protected enforcement
   point. Test unauthorized modification and binding to execution separately.

10. **Link peer-review claims to a venue.** The matrix calls CaMeL “peer-reviewed
    arXiv.” The cited arXiv page is a versioned paper source; that phrase alone
    does not establish peer review. Add a proceedings/journal link if verified,
    or describe it as the authors' paper and reported evaluation.

11. **Use the latest runnable evidence.** Replacing “test file exists” with a
    successful test requires recording runtime and exit status. Our latest
    report includes the known socket failures and unavailable OS separation;
    those cannot be upgraded to passes by an “enforced” badge.

12. **Turn promising gaps into small matched experiments.** For each chosen
    property, include a legitimate task, an adversarial request, effect counts,
    a safeguard-removal control and restart/concurrency cases where relevant.
    Reuse identical tasks and budgets across systems. Treat source-visibility
    experiments as proposed until model versions, randomization, sample counts
    and outcomes have actually been recorded.

## Applying the earlier source-visibility advice

Grok's recommendations to separate OS identities, remove real credentials from
the agent and keep deployed mutable state protected are useful. “The model must
never see the code” is not the definition of a reference monitor. NIST describes
complete mediation, resistance to tampering and verifiability; source secrecy is
not among those requirements.
[NIST reference monitor definition](https://csrc.nist.gov/glossary/term/reference_monitor).

Our engineering conclusion is to minimize operational access while testing with
source-aware attackers too. Public source knowledge must not let an agent replace
the governor, mint approvals, change the database or reach an unmediated effect.
That conclusion is a design requirement, not a result showing visibility has no
effect on attack success.

The cumulative repository already contains the standalone client and bounded
agent-facing refusals in `agent/`, and the A–E experiment plan in
`GOVERNANCE_OBSERVABILITY.md`. Minimum sufficient refusal guidance gives a safe
next step without echoing private callback details. The new artifact code stays
on the trusted side; its session/capture/review APIs are not added to that client.

The operational deployment still needs a real restricted-account bypass test.
This environment cannot demonstrate that OS boundary. Publishing the source or
keeping it private does not resolve an untested deployment boundary.
