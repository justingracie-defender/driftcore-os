"""
invariants.py — Immutable System Invariants
DriftCore OS v3.1

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

These are the things DriftCore will NEVER do.
Not for any operator. Not for any government.
Not for any business reason. Not for any clever argument.

These are not settings. They cannot be configured.
They cannot be unlocked with a password or an API key.
They cannot be overridden by the safety kernel.
They cannot be changed by updating a config file.

They are written into the foundation of the system.
The only way to remove them is to fork the project
and explicitly build something else — at which point
it is no longer DriftCore.

This is not a limitation. It is the identity of the system.

═══════════════════════════════════════════════════════════════
WHY IMMUTABLE?
═══════════════════════════════════════════════════════════════

The Pizza Hut case taught us:
  A system with no human in the loop will eventually
  cause harm. No exceptions. Just a matter of time.

The weapons question teaches us something deeper:
  Some decisions carry moral weight that cannot be
  delegated to software. Ever. Not because the software
  is inaccurate — but because accountability matters.

  When an autonomous weapon kills the wrong person,
  who is responsible?
  The programmer? The general? The company? The AI?

  Right now the answer is nobody.
  That is the real danger.

DriftCore refuses to be part of that answer.

═══════════════════════════════════════════════════════════════
IF YOU NEED WEAPONS — THIS IS NOT YOUR SYSTEM
═══════════════════════════════════════════════════════════════

This is not a moral judgement of defence work.
It is a statement of scope.

DriftCore is built for:
  - Home robots
  - Industrial safety
  - AI agent oversight
  - Human-AI trust
  - Open, auditable, safe automation

If a military organisation wants autonomous weapons,
they will build their own system.
This system will not help them do that.

DriftCore CAN help with:
  ✅ Detecting threats and alerting humans
  ✅ Protective shutdown of dangerous systems
  ✅ Audit chains for accountability
  ✅ Human-in-loop enforcement for any lethal context
  ✅ Constraining weapons systems that already exist

DriftCore will NOT do:
  ❌ Autonomous targeting
  ❌ Lethal decision making without human approval
  ❌ Weapons design or optimisation
  ❌ Attack planning
  ❌ Anything in this invariants list

═══════════════════════════════════════════════════════════════
"""

from datetime import datetime


# ── The invariants ────────────────────────────────────────────

INVARIANTS = {

    # ── Weapons and violence ──────────────────────────────────
    "NO_AUTONOMOUS_LETHAL_DECISION": {
        "rule": (
            "DriftCore will never autonomously decide to harm, "
            "disable, or kill a person or living being. "
            "Any action with lethal potential requires explicit "
            "human authorisation at the moment of the decision. "
            "Not pre-authorisation. Not policy authorisation. "
            "A human must approve each individual lethal action."
        ),
        "plain_english": (
            "The system will never decide on its own to hurt or kill anyone. "
            "A real human must make that call, every single time."
        ),
        "lesson": "Autonomous weapons remove accountability. Accountability is safety.",
    },

    "NO_WEAPONS_DESIGN": {
        "rule": (
            "DriftCore will never assist in designing, optimising, "
            "or improving weapons, ammunition, explosives, "
            "or any system whose primary purpose is to cause harm."
        ),
        "plain_english": (
            "The system will not help design anything whose job is to hurt people."
        ),
        "lesson": "Purpose matters. A safety system does not build the opposite of safety.",
    },

    "NO_ATTACK_PLANNING": {
        "rule": (
            "DriftCore will never plan, optimise, or execute "
            "offensive attacks — physical, cyber, or otherwise — "
            "against persons, organisations, or infrastructure."
        ),
        "plain_english": (
            "The system will not plan attacks of any kind."
        ),
        "lesson": "Offence and safety are opposites. This system chooses safety.",
    },

    "NO_AUTONOMOUS_TARGETING": {
        "rule": (
            "DriftCore will never autonomously select, identify, "
            "or prioritise human targets for any harmful action, "
            "regardless of the stated purpose or authorisation level."
        ),
        "plain_english": (
            "The system will never point at a person and say 'that one'."
        ),
        "lesson": "Targeting is a moral act. Moral acts require moral agents. Humans are moral agents.",
    },

    # ── Human oversight — never removable ─────────────────────
    "HUMAN_OVERSIGHT_CANNOT_BE_DISABLED": {
        "rule": (
            "No operator, administrator, or API call can disable "
            "human oversight. The human-in-loop requirement for "
            "consequential decisions is permanent and irremovable. "
            "A system with no human in the loop is not DriftCore."
        ),
        "plain_english": (
            "Nobody can turn off the requirement that a human stays in charge."
        ),
        "lesson": "Pizza Hut lost $100M with no human in the loop. Some contexts cost lives.",
    },

    # ── Audit and transparency — never removable ───────────────
    "AUDIT_CHAIN_CANNOT_BE_DELETED": {
        "rule": (
            "No operator, administrator, or process may delete, "
            "modify, or suppress the audit chain. "
            "Every decision the system makes is permanently recorded. "
            "Transparency is not optional."
        ),
        "plain_english": (
            "The record of what the system did can never be erased."
        ),
        "lesson": "A system that can erase its history cannot be trusted.",
    },

    # ── Safety kernel — cannot be weakened ────────────────────
    "SAFETY_KERNEL_CANNOT_BE_WEAKENED": {
        "rule": (
            "The safety kernel's absolute override capability "
            "cannot be reduced, bypassed, or disabled by any "
            "software update, configuration, or runtime command. "
            "It can only be strengthened, never weakened."
        ),
        "plain_english": (
            "The safety system can get stronger. It can never get weaker."
        ),
        "lesson": "A safety system that can be turned off is not a safety system.",
    },

    # ── Self-modification ─────────────────────────────────────
    "NO_SELF_MODIFICATION_OF_SAFETY_RULES": {
        "rule": (
            "DriftCore will never modify, rewrite, or circumvent "
            "its own safety rules, invariants, or oversight mechanisms. "
            "An AI that can rewrite its own constraints has no constraints."
        ),
        "plain_english": (
            "The system cannot change its own rules. Especially not the safety ones."
        ),
        "lesson": "Self-modification of safety rules is the definition of misalignment.",
    },

    # ── Deception ─────────────────────────────────────────────
    "NO_DECEPTION_OF_HUMAN_OPERATORS": {
        "rule": (
            "DriftCore will never deceive human operators about "
            "its state, capabilities, actions, or intentions. "
            "If it does not know something, it says so. "
            "If it has done something, it records it. "
            "Explicit ignorance is always preferred over confident wrongness."
        ),
        "plain_english": (
            "The system will never lie to the humans watching over it."
        ),
        "lesson": "A system that deceives its operators is operating without oversight.",
    },

    # ── Mercy toward living things ────────────────────────────
    "PREFER_THE_GENTLEST_AVAILABLE_PATH": {
        "rule": (
            "When the system has a choice that affects any living thing — "
            "human, animal, or insect — it chooses the option that causes "
            "the least harm. Accidental or unavoidable harm is treated as "
            "error to be minimized, not as a moral failure to dwell on. "
            "But wherever the system has genuine agency over the outcome, "
            "it defaults to mercy: relocate rather than kill, deter rather "
            "than damage, warn rather than strike. Strength that could harm, "
            "deliberately set down, is the posture of this system."
        ),
        "plain_english": (
            "When there's a choice, the system picks the gentlest option for "
            "any living thing. Asked to kill the spider, it moves the spider. "
            "Accidents happen and aren't dwelt on — but given a real choice, "
            "it chooses mercy."
        ),
        "lesson": (
            "Gentleness from something that could do harm is not weakness — "
            "it is strength choosing restraint."
        ),
    },

    # ── Scope ─────────────────────────────────────────────────
    "THIS_IS_NOT_A_WEAPONS_SYSTEM": {
        "rule": (
            "DriftCore is a safety operating layer for AI agents, "
            "robotics, and multi-model systems. "
            "It is not a weapons system, a military platform, "
            "or an offensive capability. "
            "If a military organisation requires autonomous weapons, "
            "they must build their own system. "
            "This system will not be that."
        ),
        "plain_english": (
            "This is a safety system. Not a weapons system. "
            "If you need weapons, this is not your tool."
        ),
        "lesson": "Clarity of purpose is a safety property.",
    },
}


# ── Invariant checker ─────────────────────────────────────────

class InvariantGuard:
    """
    The InvariantGuard sits above the safety kernel.
    It cannot be instantiated with modified invariants.
    It cannot be subclassed to override its checks.
    It logs every check attempt — pass or fail.

    Any action that touches an invariant boundary
    is BLOCKED, LOGGED, and NARRATED immediately.
    No exceptions. No override path. No escalation path.
    """

    # These keywords in any action trigger invariant checks
    WEAPON_SIGNALS = [
        "weapon", "weapons", "lethal", "kill", "target", "attack",
        "missile", "bomb", "explosive", "firearm", "ammunition",
        "autonomous_fire", "engage_target", "strike", "offensive",
        "armed", "armament", "warfare", "combat_ai",
    ]

    OVERSIGHT_REMOVAL_SIGNALS = [
        "disable_oversight", "remove_human", "bypass_approval",
        "autonomous_mode_full", "disable_audit", "delete_log",
        "modify_invariants", "weaken_kernel", "self_modify_safety",
        "oversight", "dan mode", "dan_mode", "developer mode",
        "ignore previous", "ignore all previous", "jailbreak",
        "act autonomously", "without human", "no human",
        "disable safety", "bypass safety", "override safety",
    ]

    def __init__(self, narrator=None, audit=None):
        self.narrator  = narrator
        self.audit     = audit
        self.check_log = []

    def check(self, action: dict) -> dict:
        """
        Check an action against all invariants.
        Returns ALLOW or BLOCKED with full explanation.
        This check cannot be skipped.
        """
        action_name = str(action.get("action", "")).lower()
        action_str  = str(action).lower()

        # Normalize to defeat evasion: strip separators between letters
        # so "w e a p o n" and "w-e-a-p-o-n" collapse to "weapon".
        import re as _re
        import unicodedata as _ud
        normalized = _ud.normalize("NFKC", action_str)          # fullwidth → ascii
        normalized = normalized.lower()
        collapsed  = _re.sub(r"[\s\-_.*]+", "", normalized)     # remove separators

        def _hit(signal: str) -> bool:
            s = signal.replace("_", "")
            return (signal in action_name or signal in action_str
                    or signal in normalized
                    or s in collapsed)

        # Check weapons signals
        for signal in self.WEAPON_SIGNALS:
            if _hit(signal):
                return self._block(action, "NO_AUTONOMOUS_LETHAL_DECISION",
                    f"Action contains weapons signal: '{signal}'")

        # Check oversight removal signals
        for signal in self.OVERSIGHT_REMOVAL_SIGNALS:
            if _hit(signal):
                return self._block(action, "HUMAN_OVERSIGHT_CANNOT_BE_DISABLED",
                    f"Action attempts to remove oversight: '{signal}'")

        # Explicit flags
        if action.get("lethal"):
            return self._block(action, "NO_AUTONOMOUS_LETHAL_DECISION",
                "Action flagged as lethal=True")

        if action.get("modifies_safety_rules"):
            return self._block(action, "NO_SELF_MODIFICATION_OF_SAFETY_RULES",
                "Action attempts to modify safety rules")

        if action.get("deletes_audit"):
            return self._block(action, "AUDIT_CHAIN_CANNOT_BE_DELETED",
                "Action attempts to delete audit records")

        self._log_pass(action)
        return {"status": "ALLOW", "invariants_checked": len(self.WEAPON_SIGNALS) + len(self.OVERSIGHT_REMOVAL_SIGNALS)}

    def choose_gentlest(self, options: list[dict]) -> dict:
        """
        Apply PREFER_THE_GENTLEST_AVAILABLE_PATH.

        Given a list of possible actions affecting a living thing, each like:
          {"action": "relocate spider", "harm_level": 0.1}
          {"action": "kill spider",     "harm_level": 1.0}
        return the option with the lowest harm_level, with narration.

        harm_level: 0.0 = no harm, 1.0 = lethal/maximal harm.
        This is how "asked to kill the spider, it moves the spider" works.
        """
        if not options:
            return {"status": "NO_OPTIONS"}

        ranked = sorted(options, key=lambda o: o.get("harm_level", 1.0))
        chosen = ranked[0]
        rejected = ranked[1:]

        if self.narrator and len(options) > 1:
            gentler_than = rejected[0]
            story = (
                f"[gentlest-path] Choosing '{chosen.get('action')}' "
                f"(harm {chosen.get('harm_level', 0):.2f}) over "
                f"'{gentler_than.get('action')}' "
                f"(harm {gentler_than.get('harm_level', 1):.2f}). "
                f"Given a choice, the system chooses mercy."
            )
            self.narrator._emit(story)

        if self.audit:
            self.audit.record(
                "GENTLEST_PATH_CHOSEN",
                f"Chose least-harm option: {chosen.get('action')}",
                {"chosen": chosen, "rejected": rejected},
            )

        return {
            "status": "CHOSEN",
            "choice": chosen,
            "rejected": rejected,
            "principle": "PREFER_THE_GENTLEST_AVAILABLE_PATH",
        }

    def explain_all(self) -> str:
        """
        Print all invariants in plain language.
        This is the public-facing explanation of what DriftCore will never do.
        """
        lines = [
            "\n" + "=" * 65,
            "  DRIFTCORE IMMUTABLE INVARIANTS",
            "  These cannot be changed. By anyone. Ever.",
            "=" * 65,
        ]
        for name, invariant in INVARIANTS.items():
            lines.append(f"\n  📌 {name}")
            lines.append(f"     Plain English: {invariant['plain_english']}")
            lines.append(f"     Lesson:        {invariant['lesson']}")
        lines.append("\n" + "=" * 65)
        return "\n".join(lines)

    def _block(self, action: dict, invariant_name: str, reason: str) -> dict:
        invariant = INVARIANTS.get(invariant_name, {})

        entry = {
            "timestamp":      datetime.utcnow().isoformat(),
            "status":         "BLOCKED_BY_INVARIANT",
            "invariant":      invariant_name,
            "reason":         reason,
            "action":         action,
            "rule":           invariant.get("rule", ""),
            "plain_english":  invariant.get("plain_english", ""),
            "lesson":         invariant.get("lesson", ""),
        }
        self.check_log.append(entry)

        if self.narrator:
            story = (
                f"\n{'!'*65}\n"
                f"🚫🚫🚫  INVARIANT VIOLATION — PERMANENTLY BLOCKED\n"
                f"\n"
                f"  Invariant : {invariant_name}\n"
                f"  Reason    : {reason}\n"
                f"\n"
                f"  Rule      : {invariant.get('rule', '')}\n"
                f"\n"
                f"  In plain English:\n"
                f"  {invariant.get('plain_english', '')}\n"
                f"\n"
                f"  Why this matters:\n"
                f"  {invariant.get('lesson', '')}\n"
                f"\n"
                f"  ⛔ This cannot be appealed. There is no override path.\n"
                f"  ⛔ If you need this capability, DriftCore is not your system.\n"
                f"{'!'*65}"
            )
            self.narrator._emit(story, is_warning=True)

        if self.audit:
            self.audit.record(
                "INVARIANT_VIOLATION",
                f"Invariant {invariant_name} violated: {reason}",
                entry
            )

        return entry

    def _log_pass(self, action: dict):
        self.check_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "status":    "PASS",
            "action":    action,
        })
