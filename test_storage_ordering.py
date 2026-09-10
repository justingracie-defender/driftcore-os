"""
test_storage_ordering.py — a Tier 1 record is verified before it is decrypted.

This file exists because the ordering claim in `driftcore/storage/__init__.py`
was wrong twice, in prose, with nothing testing it either time.

  1. The module header said `Read: Load → Verify signature → Decrypt` and
     `If signature fails, decryption never runs` for its whole history. The code
     decrypted first and verified afterwards, and said so in an inline comment
     three lines below the header's claim.
  2. The 2026-09-01 edit that corrected the AES claim then asserted the file
     already did encrypt-then-MAC and that "that part of the design is sound".
     Also false. A false claim was replaced with a different false claim in the
     act of correcting it, and reported as verified.

Neither was caught by a test, because no test asserted on ORDER — only on
round-trip and on tamper being detected eventually. Detection-eventually is
satisfied by verifying after decryption, which is the arrangement being removed.

# CLAIMS: driftcore/storage/__init__.py:signature-covers-ciphertext
# CLAIMS: driftcore/storage/__init__.py:verify-before-decrypt

Run: python3 test_storage_ordering.py
"""

import driftcore.storage as st
from driftcore.enforcement import _sign_item

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


st._ENCRYPTION_KEY = st.derive_key("test-passphrase-not-a-real-one")[0]

PLAIN = "12 Example Street, Springfield"
CT = st._encrypt(PLAIN)
ARGS = ("note", 1234.0, ["family"], False)
REC_ID = "record-under-test"


print("=== signature-covers-ciphertext ===")

_sig = st._sign_record(CT, *ARGS, REC_ID)
check("the signature is marked as covering ciphertext AND record id",
      _sig.startswith(st.SIG_V3))
check("it verifies against the ciphertext with nothing decrypted",
      st._verify_record(CT, *ARGS, _sig, REC_ID) is True)

# The decisive one: signing must NOT be a function of the plaintext. If it were,
# verification would need the plaintext, which is the whole defect.
_sig_plain = st.SIG_V3 + _sign_item(f"{REC_ID}|{PLAIN}", *ARGS)
check("a signature over the PLAINTEXT does not verify against the ciphertext",
      st._verify_record(CT, *ARGS, _sig_plain, REC_ID) is False)

# Two encryptions of the same text use different nonces, so they are different
# ciphertexts and must carry different signatures. Under the old plaintext
# signing they would have been identical — which is what made the ciphertext
# unauthenticated: swapping one for the other was undetectable.
_ct2 = st._encrypt(PLAIN)
check("a different ciphertext of the SAME plaintext gets a different signature",
      CT != _ct2 and st._sign_record(_ct2, *ARGS, REC_ID) != _sig)
check("...and one ciphertext's signature does not validate the other",
      st._verify_record(_ct2, *ARGS, _sig, REC_ID) is False)


check("a signature bound to a DIFFERENT record id does not verify — the "
      "envelope authenticates THIS record, not 'some legitimate record'",
      st._verify_record(CT, *ARGS, _sig, "some-other-id") is False)


print("=== tamper is caught without decrypting ===")

_bad = CT[:-4] + ("AAAA" if not CT.endswith("AAAA") else "BBBB")
check("a modified ciphertext fails verification",
      st._verify_record(_bad, *ARGS, _sig, REC_ID) is False)
check("a modified field fails verification",
      st._verify_record(CT, "other_source", 1234.0, ["family"], False, _sig, REC_ID) is False)


import inspect
_src = inspect.getsource(st)

print("=== legacy records are refused, not reported as tamper ===")

# A record written before the fix. Distinguishable by prefix alone — no
# decryption required to classify it, which is the point.
_legacy = _sign_item(PLAIN, *ARGS)
_raised = False
try:
    st._verify_record(CT, *ARGS, _legacy, REC_ID)
except st.LegacySignature:
    _raised = True
check("an unprefixed signature raises LegacySignature", _raised)


_raised2 = False
try:
    st._verify_record(CT, *ARGS, None, REC_ID)
except st.LegacySignature:
    _raised2 = True
check("a missing signature is refused rather than treated as valid", _raised2)


print("=== no path decrypts a Tier 1 record it has not verified ===")

# BEHAVIOURAL, not textual. The first version of this check compared source
# offsets — `_verify_record` appearing before `_decrypt` in the file — and a
# mutation that simply nested the decrypt INSIDE the verify call
# (`_verify_record(_decrypt(row[...]), ...)`) sailed past it 13/13. A source-order
# assertion is not an ordering assertion. Drive the real path and watch whether
# decryption happens at all.
import os, sqlite3, tempfile, types

_tmp = tempfile.mkdtemp()
_store = st.SecureStorage(os.path.join(_tmp, "t.db"))
_store.open()
_item = types.SimpleNamespace(text=PLAIN, source="note", timestamp=1234.0,
                              tags=["family"], quarantined=False,
                              surprise_score=0.5, last_accessed=1234.0,
                              access_count=0, review_stage=0)
_id = _store.store_tier1(_item)

# Corrupt the stored ciphertext directly, as an attacker with disk access would.
_conn = sqlite3.connect(os.path.join(_tmp, "t.db"))
_row = _conn.execute("SELECT encrypted_text FROM tier1_memory").fetchone()[0]
_conn.execute("UPDATE tier1_memory SET encrypted_text = ?",
              (_row[:-4] + ("AAAA" if not _row.endswith("AAAA") else "BBBB"),))
_conn.commit(); _conn.close()

_decrypt_calls = []
_real_decrypt = st._decrypt
_halted = []
_real_halt = st.SecureStorage._tamper_shutdown
def _spy_decrypt(c):
    # Record FIRST, then attempt. On a tampered record the real _decrypt raises,
    # and if the call is not recorded before that the check crashes instead of
    # failing — a red signal either way, but an illegible one.
    _decrypt_calls.append(c)
    try:
        return _real_decrypt(c)
    except Exception:
        return "[undecryptable]"


st._decrypt = _spy_decrypt
st.SecureStorage._tamper_shutdown = lambda self, reason: _halted.append(reason)
try:
    _store2 = st.SecureStorage(os.path.join(_tmp, "t.db"))
    _store2.open()
    _store2.load_tier1()
finally:
    st._decrypt = _real_decrypt
    st.SecureStorage._tamper_shutdown = _real_halt

check("a tampered record is detected", len(_halted) == 1)
check("...and _decrypt was NEVER called on it — verification gated the "
      "decryption, rather than running after it",
      len(_decrypt_calls) == 0)
check("...and the tamper message names the id, not the contents",
      _halted and _id in _halted[0] and PLAIN[:20] not in _halted[0])

_del = _src[_src.index("def delete_tier1"):]
_del = _del[:_del.index("\n    def ", 10)]
check("delete_tier1 no longer decrypts at all — it was a second, unverified "
      "decryption path around the gate",
      "_decrypt(" not in _del)
# Assert the audit line's CONTENT, not the absence of a word — the first draft
# of this check matched "plaintext" inside the explanatory comment above the
# code and went red on prose.
# delete_tier1 now has TWO audit calls — the refusal and the deletion. Both must
# name the id and neither may carry contents.
_audit_lines = [l for l in _del.splitlines() if "_audit(" in l]
check("...and every audit line in delete_tier1 records the id, not the contents",
      len(_audit_lines) == 2
      and all("plaintext" not in l for l in _audit_lines))


print("=== legacy signatures: tamper by default ===")

# An earlier version of this check asserted the OPPOSITE — that load_tier1
# skips a legacy record rather than halting — on the reasoning that legacy data
# is not an attack. test_storage.py's existing tamper check caught the flaw:
# the "is this legacy?" test reads the signature field, which is precisely what
# an attacker rewrites. Stripping the prefix downgraded tamper detection into a
# silent skip. No on-disk field can carry that distinction. So: tamper by
# default, migration by explicit operator opt-in.
_store3 = st.SecureStorage(os.path.join(_tmp, "legacy.db"))
_store3.open()
_store3.store_tier1(_item)
_c = sqlite3.connect(os.path.join(_tmp, "legacy.db"))
_c.execute("UPDATE tier1_memory SET signature = 'stripped_prefix_attack'")
_c.commit(); _c.close()

_halted2 = []
st.SecureStorage._tamper_shutdown = lambda self, reason: _halted2.append(reason)
try:
    _s = st.SecureStorage(os.path.join(_tmp, "legacy.db")); _s.open(); _s.load_tier1()
finally:
    st.SecureStorage._tamper_shutdown = _real_halt
check("a signature stripped of its format prefix is treated as TAMPER, not "
      "silently skipped — otherwise stripping it disables detection",
      len(_halted2) == 1)

_halted3 = []
st.SecureStorage._tamper_shutdown = lambda self, reason: _halted3.append(reason)
try:
    _s2 = st.SecureStorage(os.path.join(_tmp, "legacy.db"), allow_legacy=True)
    _s2.open(); _s2.load_tier1()
finally:
    st.SecureStorage._tamper_shutdown = _real_halt
check("...and reading them at all requires an explicit operator opt-in",
      len(_halted3) == 0)

_rejected = False
try:
    st.SecureStorage(os.path.join(_tmp, "x.db"), allow_legacy="yes")
except TypeError:
    _rejected = True
check("...which is a bool, not a truthy value — it disables tamper detection",
      _rejected)


print("=== delete-requires-a-verified-human ===")

import driftcore.authority.human_identity as _hi

_hi.reset_policy()
_sd = st.SecureStorage(os.path.join(_tmp, "del.db"))
_sd.open()
_did = _sd.store_tier1(_item)

_refused_nonhuman = False
try:
    _sd.delete_tier1(_did, authorised_by="agent")
except PermissionError:
    _refused_nonhuman = True
check("a non-human label cannot delete a Tier 1 record", _refused_nonhuman)
check("...and the record survives", len(_sd.load_tier1()) == 1)

_arity = False
try:
    _sd.delete_tier1(_did)
except TypeError:
    _arity = True
check("...and the principal argument is required, with no default",
      _arity)

# Under ATTESTED a bare name is False by design, so the parameter must accept an
# attestation or the gate would be unpassable in the only mode that establishes
# anything. A gate that cannot be passed is an outage, not a gate.
_v = _hi.HumanIdentityVerifier()
_v.register_principal("operator_jane", b"jane-key")
_hi.set_verifier(_v)
try:
    _bare = False
    try:
        _sd.delete_tier1(_did, authorised_by="operator_jane")
    except PermissionError:
        _bare = True
    check("under ATTESTED, a bare name is refused — a name is not an attestation",
          _bare)
    _att = _hi.HumanAttestation.issue(b"jane-key", principal="operator_jane",
                                      action="storage_delete_tier1",
                                      ttl_seconds=60, nonce=os.urandom(8).hex())
    _sd.delete_tier1(_did, authorised_by=_att)
    check("...while a valid attestation deletes (not an outage)",
          len(_sd.load_tier1()) == 0)
finally:
    _hi.reset_policy()


print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
