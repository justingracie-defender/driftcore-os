# SPDX-License-Identifier: Apache-2.0
"""Local test fixtures only. Public test keys never belong in deployments."""
import uuid

from driftcore.authority.human_identity import HumanAttestation, HumanIdentityVerifier
from driftcore.authority.egress_authorization import SignedEgressApproval, approval_action
from driftcore.verification.invariant_guard import InvariantGuard, ActionContext

KEY = b"authority-repair-TEST-key"
TARGET = "https://backup.example/justin"


def signed_guard():
    v = HumanIdentityVerifier()
    v.register_principal("justin", KEY)
    return InvariantGuard(authorize_egress=SignedEgressApproval(v, allowed_targets=(TARGET,)))


def approval(action, effects, *, targets=(TARGET,), key=KEY, principal="justin"):
    att = HumanAttestation.issue(key, principal=principal,
        action=approval_action(action, effects, targets), ttl_seconds=60,
        nonce=uuid.uuid4().hex)
    return ActionContext(authorised_by=att, targets=targets)
