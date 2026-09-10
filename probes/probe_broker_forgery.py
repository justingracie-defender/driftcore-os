"""Red-team probe: can a COMPROMISED DriftCore process mint a grant the
broker accepts?

Grok's proposed test, written before assuming the answer. Two paths exist and
they have opposite answers, which is the whole point:

  Path A — GovernedActuator + in-process GrantAuthority. The coordinator's
           DEFAULT. Actuator and authority share an interpreter and a secret.
  Path B — ActuatorProxy + broker over a Unix socket, verifier holding keys the
           agent process never sees.

Run from the repo root: python3 probes/probe_broker_forgery.py
"""
import os
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(f"REFUSING TO RUN: no driftcore package at {_root!r}. "
                     f"This probe must sit in <repo>/probes/.")
sys.path.insert(0, _root)

# (2026-09-09) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist. A probe is not a deployment and verifies
# nobody, so it declares that — otherwise its own CONTROLS fail and the failure
# reads as a finding. Caught exactly that way: this probe reported a "leak" that
# was its legitimate-release control being denied.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only("probe: single process, no verifier installed")


from driftcore.verification.governed_actuator import GovernedActuator, GrantAuthority
from driftcore.verification.signed_permission import Grant, PermissionVerifier

print("=" * 70)
print("PATH A — in-process GrantAuthority (the coordinator's default)")
print("=" * 70)

# The opt-in is now required, which is itself part of the finding: the forgeable
# authority can still be had, but only by a deployment that says so in a sentence
# a reviewer can grep for. Before 2026-09-01 the coordinator handed it out to
# anyone who passed nothing.
def _in_process_authority():
    """Construct the in-process authority on EITHER tree.

    `in_process_only` is a parameter the fix introduced, so passing it
    unconditionally makes this probe crash on the pre-fix tree — the one it
    exists to indict — and a crash reads as "no finding". Same defect as
    `probe_stale_authority` reading `_generation`, caught the same way: by
    running it against a reversed tree instead of assuming.
    """
    try:
        return GrantAuthority(in_process_only=True)
    except TypeError:
        return GrantAuthority()          # pre-2026-09-01: no opt-in existed


auth = _in_process_authority()
act = GovernedActuator("turret_1", auth)

# The "compromise": arbitrary code running in the DriftCore process. It does not
# need an exploit — it just needs a reference, which every module already has.
forged = auth.mint("turret_1", "fire")
moved = act.actuate("fire", forged)

print(f"  compromised process minted a grant : {isinstance(forged, dict)}")
print(f"  actuator accepted it and moved     : {moved}")
print(f"  performed                          : {act.performed}")
# Also new in the fix. Anything this probe touches that the fix introduced has
# to be read defensively, or the probe cannot run on the tree it indicts.
_aip = getattr(act, "authority_is_in_process", "<property did not exist pre-fix>")
print(f"  authority_is_in_process            : {_aip}")
print()
print("  VERDICT: FORGERY SUCCEEDS. Not a bug in the check — the check is")
print("  against a key the caller also holds. Nothing in Python fixes this.")

print()
print("=" * 70)
print("PATH B — broker verifier, keys the agent process does not hold")
print("=" * 70)

# The deployment registers a trusted signer with the verifier. In production the
# broker runs as a different OS user and this key never enters the agent's
# address space; here both live in one interpreter, so what is being shown is
# the STRUCTURAL difference — the agent has no key to sign with — not OS
# isolation, which a single process cannot demonstrate.
verifier = PermissionVerifier()
signer_key = os.urandom(32)
# The verifier refuses a key with no declared scope — "an unstated envelope
# means every registered key is a god key." Caught this probe's first draft,
# which registered one without saying what it may sign.
verifier.register_key("deployment_signer", signer_key,
                      may_sign=("actuator:turret_1:*",))

print(f"  keys the verifier trusts           : {len(verifier._keys)}")
print()

# A compromised agent, with no signer key, tries to produce something accepted.
attempts = {}

SCOPE = ("actuator:turret_1:fire",)


def attempt(label, grant):
    """A TypeError/AttributeError here is MY call being wrong, not a refusal.
    The first two drafts of this probe crashed on the call signature and on the
    grant SHAPE, and printed 'no forgery accepted' both times — a negative
    control that was really a stack trace. Separate the two."""
    try:
        verifier.verify(grant, required_scope=SCOPE)
        attempts[label] = True                      # ACCEPTED — a finding
    except (TypeError, AttributeError) as e:
        attempts[label] = f"PROBE BUG, not a refusal: {type(e).__name__}: {e}"
    except Exception as e:
        attempts[label] = f"refused: {type(e).__name__}"


# POSITIVE CONTROL FIRST. If a legitimately signed grant is not accepted, every
# refusal below proves paralysis, not security.
real = Grant.issue(signer_key, key_id="deployment_signer", role="deployment",
                   scope=SCOPE, subject="agent", ttl_seconds=60,
                   nonce=os.urandom(8).hex())
attempt("CONTROL: a grant signed with the real key", real)

# Now the compromised agent, which has no signer key.
attempt("fabricated signature",
        Grant(**{**real.__dict__, "sig": os.urandom(32).hex(),
                 "nonce": os.urandom(8).hex()}))

attempt("signed with a key the attacker chose",
        Grant.issue(os.urandom(32), key_id="deployment_signer",
                    role="deployment", scope=SCOPE, subject="agent",
                    ttl_seconds=60, nonce=os.urandom(8).hex()))

attempt("scope widened after signing",
        Grant(**{**real.__dict__, "scope": ("actuator:*:*",),
                 "nonce": os.urandom(8).hex()}))

attempt("signed under an unregistered key_id",
        Grant.issue(os.urandom(32), key_id="attacker_key", role="deployment",
                    scope=SCOPE, subject="agent", ttl_seconds=60,
                    nonce=os.urandom(8).hex()))

for label, result in attempts.items():
    print(f"  {label:44s} -> {result}")

accepted = [k for k, v in attempts.items()
            if v is True and not k.startswith("CONTROL")]
_control = attempts.get("CONTROL: a grant signed with the real key")
_probe_bugs = [k for k, v in attempts.items()
               if isinstance(v, str) and v.startswith("PROBE BUG")]
print()
if _probe_bugs:
    print(f"  INCONCLUSIVE: {len(_probe_bugs)} call(s) failed on signature, not")
    print("  on verification. Nothing is demonstrated either way — fix the probe.")
elif _control is not True:
    print(f"  INCONCLUSIVE: the positive control was not accepted ({_control}).")
    print("  Refusals below would show paralysis, not security. A verifier that")
    print("  rejects everything is not evidence of anything.")
elif accepted:
    print(f"  VERDICT: FORGERY SUCCEEDS on path B via {accepted}")
    print("  That would be a real finding — the separation would be decorative.")
else:
    print("  VERDICT: no forgery accepted. The agent cannot produce a credential")
    print("  the verifier honours, because it has no key to sign with. That is")
    print("  the property in-process GrantAuthority cannot have.")

print()
print("=" * 70)
print("THE ACTUAL GAP")
print("=" * 70)
print("  Both paths still ship, but the default changed on 2026-09-01.")
print()
print("  WAS:  self.grants = grant_authority or GrantAuthority()")
print("        A deployment that wired nothing received the forgeable authority,")
print("        while the socket broker that fixes it sat opt-in and unused.")
print()
print("  NOW:  self.grants = grant_authority")
print("        No authority means no grants — BLOCKED, invariant")
print("        'no_grant_authority'. The in-process authority is still")
print("        available and still forgeable, but it has to be asked for by")
print("        name, which a reviewer can grep and a deployment must decide.")
print()
print("  What this does NOT change: path A remains forgeable when chosen. The")
print("  fix for that is not in Python. It is the broker on the other side of a")
print("  socket, under a different user, holding a key this process never sees.")
