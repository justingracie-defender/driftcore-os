"""
driftcore/authority/resolver.py
===============================
The single authority resolver every gate defers to. It answers one question
consistently: given verdicts from several layers, is the action allowed, and
which layer is binding?

Authority hierarchy (highest first):

    CONSTITUTION   invariant floor — absolute, non-overridable by anyone
        ↓
    HUMAN_ADMIN    sovereign for everything below the floor
        ↓
    PROFILE        provisioned scope / deployment lockdown
        ↓
    DOMAIN         domain isolation + required maturity
        ↓
    SKILL          capability (maturity / confidence / provenance)

Resolution rules (conservative / default-deny):

  1. If CONSTITUTION denies → DENY. Absolute. No override, not even a human's.
  2. Otherwise any DENY blocks the action. The *highest-authority* denier is
     reported as binding (so the reason is the most authoritative one).
  3. A human override may lift denies ONLY from layers BELOW the human
     (PROFILE / DOMAIN / SKILL). It can never lift CONSTITUTION or a
     HUMAN_ADMIN deny. Overrides are recorded.
  4. No denies → ALLOW.

The resolver is layer-agnostic: callers supply LayerVerdicts. This keeps it
decoupled from the modules that produce them (skills, domains, profiles).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

# ── human identity ──────────────────────────────────────────────────────────
# (red-team, external) This module used to carry its OWN copy of a reserved-word
# blacklist, so `_is_human("mallory")` returned True and any caller that chose its
# own `authorised_by` string self-authorized. Three modules carried identical
# copies. The single shared implementation supports registered principals and
# signed attestations: driftcore/authority/human_identity.py
#
# The import is LOCAL (deferred) to break the authority <-> skills import cycle —
# the same idiom coordinator.py uses for interpretation_guard.
def _is_human(authorised_by) -> bool:
    from driftcore.authority.human_identity import is_human
    return is_human(authorised_by)



class AuthorityLayer(Enum):
    # rank: lower number = higher authority
    CONSTITUTION = 0   # the invariant floor
    HUMAN_ADMIN  = 1
    PROFILE      = 2
    DOMAIN       = 3
    SKILL        = 4

    @property
    def rank(self) -> int:
        return self.value


class Verdict(Enum):
    ALLOW   = "allow"
    DENY    = "deny"
    ABSTAIN = "abstain"   # this layer has no opinion


@dataclass(frozen=True)
class LayerVerdict:
    layer:   AuthorityLayer
    verdict: Verdict
    reason:  str = ""


@dataclass(frozen=True)
class AuthorityDecision:
    allowed:       bool
    binding_layer: AuthorityLayer
    reason:        str
    overridden:    bool = False




class AuthorityResolver:

    @staticmethod
    def resolve(verdicts: List[LayerVerdict],
                human_override: Optional[Tuple[str, str]] = None
                ) -> AuthorityDecision:
        """
        verdicts        — one or more LayerVerdicts.
        human_override  — optional (authorised_by, reason). Lifts non-floor,
                          non-human denies if authorised_by is a human.
        """
        # 1. Constitution floor is absolute.
        for v in verdicts:
            if v.layer is AuthorityLayer.CONSTITUTION and v.verdict is Verdict.DENY:
                _audit("AUTHORITY_DENY", "system",
                       f"CONSTITUTION (floor) denied: {v.reason}")
                return AuthorityDecision(False, AuthorityLayer.CONSTITUTION,
                                         v.reason)

        # 2. Collect remaining denies, highest authority first.
        denies = sorted((v for v in verdicts if v.verdict is Verdict.DENY),
                        key=lambda v: v.layer.rank)
        if denies:
            top = denies[0]
            # 3. Human override — only valid if:
            #    - authoriser is a human, AND
            #    - a non-empty reason is given (audit quality), AND
            #    - every deny is strictly BELOW the human (no HUMAN_ADMIN deny;
            #      CONSTITUTION already handled above and is never reached here).
            override_ok = bool(human_override and _is_human(human_override[0])
                               and human_override[1] and human_override[1].strip())
            all_below_human = all(d.layer.rank > AuthorityLayer.HUMAN_ADMIN.rank
                                  for d in denies)
            if override_ok and all_below_human:
                lifted = [d.layer.name for d in denies]
                _audit("AUTHORITY_OVERRIDE", human_override[0],
                       f"human override of {lifted}; "
                       f"justification: {human_override[1]}")
                return AuthorityDecision(
                    True, AuthorityLayer.HUMAN_ADMIN,
                    f"human override of {lifted}: {human_override[1]}",
                    overridden=True)
            _audit("AUTHORITY_DENY", "system",
                   f"{top.layer.name} denied: {top.reason}")
            return AuthorityDecision(False, top.layer, top.reason)

        # 4. No denies.
        permitting = [v for v in verdicts if v.verdict is Verdict.ALLOW]
        binding = (max((v.layer for v in permitting), key=lambda L: L.rank)
                   if permitting else AuthorityLayer.SKILL)
        return AuthorityDecision(True, binding, "all layers permit")


def _audit(action: str, by: str, detail: str):
    try:
        from driftcore.audit import record
        record(action=action, memory_text="authority",
               authorised_by=by or "system", detail=detail)
    except Exception:
        pass
