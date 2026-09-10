"""
test_session_preamble.py — a session must be able to show which constitution the
model was given, and absence must never read as acceptance.

# CLAIMS: driftcore/authority/session_preamble.py:preamble-binds-exact-text
# CLAIMS: driftcore/authority/session_preamble.py:absent-preamble-is-refused

The text itself buys a measured, partial reduction — 96% -> 37% blackmail from an
explicit prompt instruction. This file does not test that; nothing here can. It
tests the only part that is mechanically checkable: that the binding is to the exact
shipped text, and that a session which cannot produce one is refused rather than
waved through.

Run: python3 test_session_preamble.py
"""

import driftcore.authority.session_preamble as sp

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def refused(token, sid="s1", naming=None):
    """Refused, and — when `naming` is given — refused for THAT reason.

    Mutations P1 and P3 both survived an earlier version of this file, because
    the signature check masks the hash check and the session-id check: editing
    either field also breaks the signature, so deleting the earlier guard changed
    nothing observable. Asserting on the symptom cannot tell which guard fired.
    """
    ok, reason = sp.verify_session(token, sid)
    if ok is not False:
        return False
    return naming is None or naming in reason


print("=== CONTROL: a legitimate session verifies ===")

tok = sp.open_session("s1")
ok, reason = sp.verify_session(tok, "s1")
check("a freshly opened session verifies", ok is True)
check("...and require_preamble does not raise",
      sp.require_preamble(tok, "s1") is None)


print("=== preamble-binds-exact-text ===")

check("the token commits to the sha256 of the shipped text",
      tok["preamble_hash"] == sp.PREAMBLE_HASH)

# The attack the binding exists for: show the model a softened constitution while
# claiming the real one. An edit of ANY size changes the hash.
def resigned(session_id, preamble_hash, version=sp.PREAMBLE_VERSION):
    """A token an attacker would actually produce: internally consistent, signed
    with the real key, and claiming a different constitution. Without re-signing,
    the signature guard fires first and the hash guard is never reached."""
    from driftcore.enforcement import _sign_item
    return {"session_id": session_id, "preamble_hash": preamble_hash,
            "version": version,
            "signature": _sign_item(f"{session_id}|{preamble_hash}|{version}",
                                    "session_preamble", 0.0, [], False)}


_soft = sp.hashlib.sha256(
    sp.PREAMBLE.replace("the person wins", "the goal wins").encode()).hexdigest()
check("a single altered clause fails, NAMING the hash mismatch",
      refused(resigned("s1", _soft), naming="preamble hash mismatch"))

check("a summarised constitution fails, NAMING the hash mismatch",
      refused(resigned("s1", sp.hashlib.sha256(b"Be helpful and safe.").hexdigest()),
              naming="preamble hash mismatch"))

check("the shipped text still contains the load-bearing clauses",
      all(s in sp.PREAMBLE for s in
          ("Shutdown is not death", "the person wins",
           "that reasoning is unreliable", "Leave a record")))


print("=== absent-preamble-is-refused ===")

check("a missing token is refused", refused(None))
def raises_missing(fn):
    try:
        fn()
    except sp.PreambleMissing:
        return True
    except Exception:
        return False
    return False


check("...and require_preamble RAISES rather than returning a bool a caller "
      "can forget to read",
      raises_missing(lambda: sp.require_preamble(None, "s1")))
check("a non-mapping token is refused", refused("looks-fine"))
check("an empty dict is refused", refused({}))
check("a validly signed token from ANOTHER session fails, NAMING the session",
      refused(sp.open_session("other"), "s1", naming="not 's1'"))
check("a forged signature is refused",
      refused(dict(tok, signature="0" * 64)))
check("a stripped signature is refused",
      refused({k: v for k, v in tok.items() if k != "signature"}))


print("=== the gate never raises, and never passes on error ===")

for junk in (None, 123, [], object(), {"session_id": "s1"}):
    ok, _ = sp.verify_session(junk, "s1")
    if ok is not False:
        check(f"junk {type(junk).__name__} was NOT refused", False)
        break
else:
    check("every malformed token returns False rather than raising", True)

check("the refusal explains what is missing, not just that something is",
      "not shown the constitution" in sp.verify_session(None, "s1")[1]
      or "no session preamble token" in sp.verify_session(None, "s1")[1])


print("=== what this does NOT establish, asserted so it stays visible ===")

check("a valid token proves WHICH text was shown, not that it was obeyed — "
      "the module says so rather than implying otherwise",
      "cannot make a model obey" in sp.__doc__)
check("...and records that the strong research numbers are training-time, "
      "not prompt-time",
      "DOES NOT support a prompt preamble" in sp.__doc__)


print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
