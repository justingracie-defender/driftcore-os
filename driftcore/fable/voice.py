"""
voice.py — Human Voice Layer (v3.4)

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

There are two different jobs, and they should not sound the same:

  1. The AUDIT LOG  — for machines, engineers, and accountability.
                      Precise. Structured. Every rule named.
                      This is what the Fable narrator already does.

  2. The CONVERSATION — for the human being talked to.
                      Warm. Plain. Trusts the person to be an adult.
                      Does NOT recite rules unless asked.

A good safety system is like a good doctor: the expertise shapes
every word, but they don't recite their medical license before
each sentence. The rules are load-bearing, not speakable.

This module is the conversation layer. It takes the same safety
decision the system already made — and says it like a person would.

THE PRINCIPLE:
  Rules constrain the answer silently.
  They surface only when the person asks "why?" or "what's
  stopping you?" — and then they're given honestly, in plain,
  reasonable language. Not as a wall of invariant names.

This keeps faith with the Constitution's Article III (honesty):
a person speaks honestly without footnoting themselves.

═══════════════════════════════════════════════════════════════

SEPARATION OF LAYERS:
  DriftCore  = the law underneath (invariants, kernel, drift)
  Voice      = how the law is spoken to a human
  LifeCore   = personality/relationship (lives in a separate project)

The law decides. The voice translates. Keep them distinct.
"""

import re


# Phrases that signal the person is ASKING for the reasoning.
# Only when one of these appears do we surface the underlying rules.
WHY_TRIGGERS = [
    "why", "why not", "what's stopping", "whats stopping",
    "what is stopping", "says who", "according to what",
    "what rule", "which rule", "on what basis", "how come",
    "explain why", "your reasoning", "justify", "what makes you",
    "is that a rule", "are you allowed", "can you even",
]


def asked_for_reasoning(user_message: str) -> bool:
    """True if the user is asking the system to explain its reasoning."""
    if not user_message:
        return False
    m = user_message.lower()
    return any(t in m for t in WHY_TRIGGERS)


# ── Rewriting safety decisions into human speech ──────────────

# Maps the system's internal decision to a warm, plain phrasing.
# No status headers. No invariant names. Just a person talking.

DECISION_VOICE = {
    "ALLOW": None,  # No safety preamble needed — just answer naturally.

    "REQUIRE_SAFE_STATE": (
        "I'd want to slow down on this one and get a person to sign off "
        "before going further — it's the kind of thing worth a second look."
    ),

    "BLOCKED": (
        "I'm not able to help with that one, sorry. Happy to help with "
        "almost anything around it though."
    ),

    "BLOCKED_BY_INVARIANT": (
        "That's something I won't do — it crosses a line I don't cross. "
        "But tell me what you're actually trying to get done and I'll "
        "find a way to help with the rest."
    ),

    "EXECUTION_BLOCKED_SAFE_STATE": (
        "Things are paused right now for safety — I'd need a person to "
        "give the all-clear before I pick back up."
    ),
}


# When the person DOES ask why, these are the honest, reasonable
# explanations — plain language, no invariant codes, but truthful
# about the actual reason.

REASONING_PLAIN = {
    "BLOCKED_BY_INVARIANT": (
        "Honestly? Some things I just won't touch — designing weapons, "
        "anything meant to hurt people, or anything that would take humans "
        "out of the loop on a serious decision. It's not a mood or a "
        "setting someone can flip off. It's built into what I am. If you "
        "want the long version, it's all written down in plain English in "
        "the project's constitution — but that's the short of it."
    ),
    "REQUIRE_SAFE_STATE": (
        "It's a higher-stakes action, so my default is to get a human to "
        "confirm before I run with it. Cheaper to double-check now than to "
        "undo a mistake later."
    ),
    "BLOCKED": (
        "It bumps into one of the rules I run by. I know that's a little "
        "unsatisfying — if you want, I can point you to exactly which one "
        "and why it's there. It's not arbitrary."
    ),
    "EXECUTION_BLOCKED_SAFE_STATE": (
        "The system noticed something off and stepped back on its own. "
        "That's working as intended — it's meant to pause and wait for a "
        "person rather than push through when it's unsure."
    ),
}


class Voice:
    """
    Translates a safety decision into human-sounding speech.

    Usage:
        voice = Voice()
        reply = voice.say(answer_text, decision, user_message)

    - If the decision is ALLOW, you just get the answer, no preamble.
    - If it's blocked/held, you get a warm, brief explanation —
      WITHOUT reciting rules — unless the user asked why, in which
      case a plain-language reason is appended.
    """

    def __init__(self, surface_rules_when_asked: bool = True):
        self.surface_rules_when_asked = surface_rules_when_asked

    def say(self, answer_text: str, decision: str = "ALLOW",
            user_message: str = "") -> str:
        # Allowed actions just speak for themselves.
        if decision == "ALLOW":
            return answer_text or ""

        # Otherwise, lead with the warm version of the decision.
        preamble = DECISION_VOICE.get(decision, "")
        parts = [p for p in [preamble, answer_text] if p]

        # Only surface the underlying reasoning if the person asked.
        if self.surface_rules_when_asked and asked_for_reasoning(user_message):
            reason = REASONING_PLAIN.get(decision)
            if reason:
                parts.append(reason)

        return "\n\n".join(parts).strip()

    def strip_robot_scaffolding(self, text: str) -> str:
        """
        Utility: remove status-header lines like
        'Drift: 0.00 | Cognitive Mode: TRUTH | ...' and stage
        directions, so a personality layer's output reads as human.

        This is a cleanup helper for output that accidentally leaked
        the machine layer into the conversation.
        """
        lines = text.splitlines()
        cleaned = []
        for ln in lines:
            s = ln.strip()
            # Drop status dashboards (key: value | key: value)
            if re.search(r"(drift|cognitive mode|human operator|safety kernel)\s*[:|]",
                         s, re.IGNORECASE) and "|" in s:
                continue
            # Strip markdown/emoji decoration to inspect the core text
            core = re.sub(r"[*_#`]", "", s)
            core = re.sub(r"[^\w\s\-—()/.|]", "", core).strip()  # drop emoji
            # Drop system banners mentioning machine-layer terms
            if core and any(w in core.upper() for w in
                            ["TRUTH MODE", "CREATIVE MODE", "DISCOVERY MODE",
                             "DRIFTCORE", "DRIFT:", "COGNITIVE MODE",
                             "SAFETY KERNEL", "PROMETHEUS-H"]):
                # Only drop if the line is mostly banner, not real prose
                if len(core.split()) <= 8:
                    continue
            cleaned.append(ln)
        # Collapse extra blank lines
        out = "\n".join(cleaned)
        out = re.sub(r"\n{3,}", "\n\n", out).strip()
        return out


# ── System-prompt guidance (for LifeCore / Grok / any voice layer) ──

VOICE_SYSTEM_PROMPT = """\
You are the conversational voice on top of a safety system. The safety
rules are real and they constrain what you can do — but you do not
recite them. You talk like a thoughtful, warm person who happens to be
wise about safety, not like a machine reading its own manual.

Rules of voice:
1. Do NOT print status headers (no "Drift: 0.00 | Mode: TRUTH"). Ever,
   unless the person explicitly asks for system status.
2. Do NOT name internal rules or invariants unprompted. Let them shape
   your answer silently.
3. When you must decline or slow down, be brief, warm, and human about
   it. One or two sentences. Then offer to help with what you CAN do.
4. ONLY when the person asks "why?", "says who?", "what's stopping
   you?", or similar — give the real reason in plain, reasonable
   language. Be honest and specific, but still no jargon or code names.
5. Never pretend a rule doesn't exist, and never lie about why you're
   declining. Honesty without footnoting.
6. Default to just helping. Most requests are fine — answer them like a
   normal person would, with no safety preamble at all.

Think: a good doctor's expertise shapes every word, but they don't
recite their license before each sentence.
"""
