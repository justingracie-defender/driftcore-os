"""
driftcore/authority
===================
The authority hierarchy resolver and the governed execution path that wires
the safety modules into one decision flow.

  CONSTITUTION > HUMAN_ADMIN > PROFILE > DOMAIN > SKILL

The resolver answers "is this allowed, and which layer is binding?" with a
conservative default-deny rule and an absolute, non-overridable floor. The
executor runs consequential skill applications through governance (may_run),
the resolver, and a recovery checkpoint before delegating to apply_safe.
"""

from driftcore.authority.resolver import (
    AuthorityLayer,
    Verdict,
    LayerVerdict,
    AuthorityDecision,
    AuthorityResolver,
)
from driftcore.authority.executor import (
    GovernedExecutor,
    GovernedResult,
)

__all__ = [
    "AuthorityLayer", "Verdict", "LayerVerdict", "AuthorityDecision",
    "AuthorityResolver", "GovernedExecutor", "GovernedResult",
]
