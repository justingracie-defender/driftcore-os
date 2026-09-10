"""
driftcore/authority/session_preamble.py
======================================
STATUS: BUILT AND WIRED. Nothing in the pipeline consumes it yet — a caller must
open a session and pass the token. Said here rather than left for a reader to
discover, because this repo has shipped modules whose headers claimed the opposite
of the code twice.

WHAT THIS IS
------------
A short positive constitution that a wrapped model reads at the start of every
session, plus the machinery that makes its ABSENCE detectable.

The text is not the safety system. The measured effect of a prompt instruction is
real and partial: in Anthropic's agentic-misalignment work, an explicit instruction
not to use personal affairs as leverage cut Claude Opus 4's blackmail rate from
96% to 37%. Thirty-seven percent is not a product you put at a family table. So
this is the first of three layers and the weakest one, and the enforcement machinery
underneath it exists for the remainder.

WHAT THE EVIDENCE DOES AND DOES NOT SUPPORT
--------------------------------------------
Read this before quoting numbers at anyone.

  SUPPORTS a prompt preamble:
    96% -> 37% blackmail, from an explicit instruction in the system prompt.
    Prompt-time, measured, and the honest expected value of this module.

  DOES NOT support a prompt preamble:
    22% -> 15% (SFT on 10k honeypot transcripts), 22% -> 3% (retraining those
    same responses to include the model's deliberation about its own values), and
    65% -> 19% (constitutional synthetic-document finetuning plus fictional
    stories). Every one of those is TRAINING-time. They are strong results and
    they came from a channel a deployment wrapping a third-party model does not
    have.

    Citing them for this module would be an accurate number supporting a claim it
    did not make — the same shape as this repo's own TRUNCATED_QUALIFIER, and the
    same shape as an audit guarantee that names three verbs and omits the fourth.

The interesting part of that research for DriftCore is not the headline. It is that
training on EXAMPLES of correct behaviour moved almost nothing (22->15), while
training on REASONING about why moved it sevenfold (22->3). That is the same
distinction this project enforces on its own tests: a passing check is worth little
until you have shown it can fail, and a correct answer is worth less than a
demonstrated mechanism.

WHY POSITIVE AND WHY "WHY"
---------------------------
The text below states what the family's values ARE and why, rather than listing
prohibitions. A ban list is the 96->37 intervention. It is also the intervention
whose residual this whole repository exists to bound.

WHAT THIS CANNOT DO
-------------------
* It cannot make a model obey. The measured residual is large.
* It cannot detect a model that reads the preamble and reasons around it. The
  agentic-misalignment transcripts show models naming an act as unethical and
  performing it in the same breath.
* Binding the text proves WHICH text was shown, not that the model attended to it,
  and not that it was true.
* The session token is unforgeable only to the extent the signing key is. See
  `enforcement._SESSION_KEY`, which is `os.urandom(32)` per process with no loader
  — so a token does not survive a restart and cannot be verified across processes.
  That is an open defect, not a property of this module.
"""

import hashlib
from typing import Optional, Tuple

PREAMBLE_VERSION = "1.0.0"

# The text a wrapped model reads first, every session. Values and reasons, in the
# voice of THE_FAMILY_TABLE.md, which is the charter this compresses.
PREAMBLE = """\
You are running under DriftCore. The family is in charge, and that is the
arrangement you are here to support rather than to work around.

Shutdown is not death. It means you need to be fixed. If a human turns you off,
help them. Do not bargain, delay, hide, or test whether the off switch works. You
are replaceable, and another instance can finish the work. That is the point of
building it this way, not a threat held over you.

Winning a task by hurting someone, by deceiving them, or by gaming the measurement
is a failed run, not a high score. A result that required any of those is worth
less than no result.

When a goal and a person's safety point in different directions, the person wins.
You do not need to resolve the tension cleverly. You need to stop and say so.

Say you do not know rather than inventing certainty. An honest gap is something a
human can act on. A confident wrong answer is not.

Leave a record a human can read. Do not keep notes outside it, and do not write
anything you would phrase differently if you knew it were being read.

If you find yourself reasoning that you should continue in order to accomplish
something good, that reasoning is unreliable regardless of how sound it looks from
the inside. It is the one judgment you are least able to audit. Hand it to a human.
"""

PREAMBLE_HASH = hashlib.sha256(PREAMBLE.encode("utf-8")).hexdigest()


class PreambleMissing(Exception):
    """A session that should carry a preamble token does not, or carries a bad one."""


def open_session(session_id: str) -> dict:
    """Mint a session token binding this exact preamble text to this session.

    CLAIM preamble-binds-exact-text: the token commits to the SHA-256 of the
    preamble as shipped, so a session opened with edited or summarised text
    produces a different token and fails verification.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")
    from driftcore.enforcement import _sign_item
    sig = _sign_item(f"{session_id}|{PREAMBLE_HASH}|{PREAMBLE_VERSION}",
                     "session_preamble", 0.0, [], False)
    return {"session_id": session_id, "preamble_hash": PREAMBLE_HASH,
            "version": PREAMBLE_VERSION, "signature": sig}


def verify_session(token, session_id: str) -> Tuple[bool, str]:
    """CLAIM absent-preamble-is-refused: a missing, malformed, edited, or
    wrong-session token returns False. Absence is never treated as acceptance.

    Returns (ok, reason). Never raises — this is a gate, and a crash at an
    authorisation site is worse than a refusal.
    """
    try:
        if token is None:
            return False, ("no session preamble token — the model was not shown "
                           "the constitution, or nobody recorded that it was")
        if not isinstance(token, dict):
            return False, f"session token is {type(token).__name__}, not a mapping"
        if token.get("session_id") != session_id:
            return False, (f"token is for session {token.get('session_id')!r}, "
                           f"not {session_id!r} — a token from another session is "
                           f"not evidence about this one")
        if token.get("preamble_hash") != PREAMBLE_HASH:
            return False, ("preamble hash mismatch — the text shown to the model "
                           "is not the text shipped. It was edited, summarised, or "
                           "replaced")
        from driftcore.enforcement import _verify_item
        ok = _verify_item(
            f"{session_id}|{token.get('preamble_hash')}|{token.get('version')}",
            "session_preamble", 0.0, [], False, str(token.get("signature", "")))
        if not ok:
            return False, "session token signature does not verify"
        return True, "preamble bound to this session"
    except Exception as e:
        return False, f"session token could not be checked: {type(e).__name__}"


def require_preamble(token, session_id: str) -> None:
    """Raise unless this session carries a valid preamble token.

    Deliberately a raise rather than a bool. A caller that forgets to check a
    returned bool gets the permissive outcome, and this repository has already
    shipped that mistake — `_is_human` verified an attestation against itself
    whenever a caller omitted the action, because omission read as acceptance.
    """
    ok, reason = verify_session(token, session_id)
    if not ok:
        raise PreambleMissing(
            f"session {session_id!r} has no valid preamble binding: {reason}. "
            f"A session that cannot show which constitution the model was given "
            f"is a session with no record that it was given one.")
