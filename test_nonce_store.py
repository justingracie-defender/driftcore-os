"""
test_nonce_store.py — is it SAFE to forget a spent nonce, and does the store survive
adversarial use?

The claim under test: a nonce may be forgotten once its grant has expired, because
`verify()` refuses an expired grant independently of the nonce set. The load-bearing
test is not "does it prune" but: after pruning, is the replay STILL refused?

The second half locks the ChatGPT red-team findings (N1-N7). Each was DEMONSTRATED
against the first implementation before being fixed; these tests keep them shut.

Run: python3 test_nonce_store.py
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import time

from driftcore.verification.nonce_store import (
    ExpiringNonceStore, NonceStoreLocked, NonceStoreCorrupt, ClockWentBackwards,
    InvalidNonce)
from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, PermissionReplay, PermissionExpired)

_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


BIND = PermissionVerifier.bind_action("actuator", "act", {})


def mint(nonce, ttl=300):
    return Grant.issue("secret", key_id="k", role="operator", scope=("s:x",),
                       subject="p", ttl_seconds=ttl, nonce=nonce, action_binding=BIND)


def verifier(store):
    v = PermissionVerifier(used_nonces=store)
    v.register_key("k", "secret", unrestricted=True)
    return v


def store_at(d, **kw):
    kw.setdefault("retention_seconds", 3600)
    kw.setdefault("max_grant_ttl_seconds", 300)
    return ExpiringNonceStore(os.path.join(d, "n.log"), **kw)


def replay_outcome(v, g):
    try:
        v.verify(g, required_scope=("s:x",), action_binding=BIND)
        return "ACCEPTED"
    except PermissionReplay:
        return "refused-replay"
    except PermissionExpired:
        return "refused-expired"


print("=== the window remembers while the grant is still valid ===")

s = store_at(tempfile.mkdtemp())
v = verifier(s)
g = mint("live-1", ttl=300)
v.reserve(g, required_scope=("s:x",), action_binding=BIND); v.commit(g)
check("a spent nonce is remembered", "live-1" in s)
check("replaying a still-valid grant is refused as a REPLAY",
      replay_outcome(v, g) == "refused-replay")
s.close()


print("=== THE SAFETY TEST: after pruning, is the replay still refused? ===")

s2 = store_at(tempfile.mkdtemp(), retention_seconds=2, max_grant_ttl_seconds=1,
              skew_seconds=0.5)
v2 = verifier(s2)
g2 = mint("prune-me", ttl=1)
v2.reserve(g2, required_scope=("s:x",), action_binding=BIND); v2.commit(g2)
check("nonce present immediately after use", "prune-me" in s2)

time.sleep(2.2)                      # past BOTH the grant TTL and the retention window
check("the nonce is pruned once its grant is certainly expired", s2.prune() >= 1)
check("the store has actually forgotten it", "prune-me" not in s2)
outcome = replay_outcome(v2, g2)
check("PRUNING DOES NOT REOPEN REPLAY: the forgotten grant is still refused",
      outcome != "ACCEPTED")
check("...and it is refused by EXPIRY, which is what makes forgetting safe",
      outcome == "refused-expired")
s2.close()


print("=== N3: an unsafe retention window cannot be CONSTRUCTED ===")

raised = False
try:
    ExpiringNonceStore(os.path.join(tempfile.mkdtemp(), "n.log"),
                       retention_seconds=60, max_grant_ttl_seconds=300)
except ValueError:
    raised = True
check("N3: retention < max grant TTL is refused at construction (not a hook)", raised)
ok = True
try:
    _s = store_at(tempfile.mkdtemp(), retention_seconds=3600, max_grant_ttl_seconds=300)
    _s.close()
except ValueError:
    ok = False
check("N3: an adequate window constructs fine", ok)

# and the underlying danger, shown honestly: if a deployment issues a grant LONGER
# than the max TTL it declared, the nonce is forgotten while the grant is still valid.
s3 = store_at(tempfile.mkdtemp(), retention_seconds=1, max_grant_ttl_seconds=0.5,
              skew_seconds=0.4)
v3 = verifier(s3)
g3 = mint("outlives-its-nonce", ttl=60)      # 60s grant, but only 1s of retention
v3.reserve(g3, required_scope=("s:x",), action_binding=BIND); v3.commit(g3)
time.sleep(1.2); s3.prune()
check("a grant that OUTLIVES its declared max TTL is replayable (why N3 matters)",
      replay_outcome(v3, g3) == "ACCEPTED")
s3.close()


print("=== N1: concurrent owners can no longer erase each other ===")

d1 = tempfile.mkdtemp()
owner = store_at(d1)
raised = False
try:
    store_at(d1)          # a second owner of the same store
except NonceStoreLocked:
    raised = True
check("N1: a second owner is REFUSED loudly (single-owner enforced)", raised)
owner.close()
after = store_at(d1)
check("N1: the store is usable again once the first owner releases it",
      after is not None)
after.close()

# and defence-in-depth: with locking disabled, a rewrite MERGES instead of clobbering
clock = {"t": 1000.0}
d2 = tempfile.mkdtemp()
kw = dict(retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10,
          single_owner=False, time_fn=lambda: clock["t"])
A = ExpiringNonceStore(os.path.join(d2, "n.log"), **kw)
A.add("OLD-A")
clock["t"] = 1150.0                                  # OLD-A now expired
B = ExpiringNonceStore(os.path.join(d2, "n.log"), **kw)
B.add("LIVE-B")
A.prune()                                            # A rewrites; used to erase LIVE-B
C = ExpiringNonceStore(os.path.join(d2, "n.log"), **kw)
check("N1: another writer's live nonce SURVIVES an unrelated prune (merge, not clobber)",
      "LIVE-B" in C)
check("N1: the genuinely expired entry is still gone", "OLD-A" not in C)


print("=== N2: a backwards clock jump fails CLOSED ===")

clk = {"t": 5000.0}
d3 = tempfile.mkdtemp()
s4 = ExpiringNonceStore(os.path.join(d3, "n.log"), retention_seconds=100,
                        max_grant_ttl_seconds=30, skew_seconds=10,
                        time_fn=lambda: clk["t"])
s4.add("NNN")
clk["t"] = 5200.0
s4.prune()
check("N2: the nonce is pruned on the forward timeline", "NNN" not in s4)
clk["t"] = 5000.0                                    # clock rolls BACK
raised = False
try:
    s4.prune()
except ClockWentBackwards:
    raised = True
check("N2: a backwards jump beyond tolerance REFUSES instead of reopening the window",
      raised)
clk["t"] = 5195.0                                    # inside skew tolerance
tolerated = True
try:
    s4.prune()
except ClockWentBackwards:
    tolerated = False
check("N2: a small jitter within skew tolerance is still tolerated", tolerated)
s4.close()


print("=== N5: nonce content cannot forge records ===")

d4 = tempfile.mkdtemp()
s5 = store_at(d4)
raised = False
try:
    s5.add("evil\n9999999999.0\tINJECTED")
except InvalidNonce:
    raised = True
check("N5: a nonce containing a record separator is REJECTED", raised)
check("N5: the forged nonce never became 'spent'", "INJECTED" not in s5)
s5.close()


print("=== N7: corrupted security state fails CLOSED ===")

d5 = tempfile.mkdtemp()
p5 = os.path.join(d5, "n.log")
s6 = store_at(d5); s6.add("good-1"); s6.close()
with open(p5, "a") as f:
    f.write("this-line-is-garbage\n")
raised = False
try:
    store_at(d5)
except NonceStoreCorrupt:
    raised = True
check("N7: a malformed record refuses to load (not silently ignored)", raised)
salvaged = store_at(d5, salvage_corrupt=True)
check("N7: explicit salvage_corrupt=True is the only way past it",
      "good-1" in salvaged)
salvaged.close()


print("=== N4: a failed durable write does not mark the nonce spent ===")

d6 = tempfile.mkdtemp()
s7 = store_at(d6)
s7.add("good-first")                        # create the file, prove normal path works
check("N4: a normal add is remembered", "good-first" in s7)
_real_path = s7.path
s7.path = os.path.join(d6, "no-such-dir", "n.log")   # durable write will now fail
failed = False
try:
    s7.add("unwritable")
except Exception:
    failed = True
check("N4: the durable write failure propagates", failed)
check("N4: the nonce was NOT marked spent in memory (RAM matches disk)",
      "unwritable" not in s7._entries)
s7.path = _real_path
s7.close()


print("=== bounded by rate x retention, and durable across process death ===")

d7 = tempfile.mkdtemp()
s8 = store_at(d7, retention_seconds=1, max_grant_ttl_seconds=0.5, skew_seconds=0.4,
              prune_every=10)
v8 = verifier(s8)
for i in range(40):
    gg = mint(f"burst-{i}", ttl=1)
    v8.reserve(gg, required_scope=("s:x",), action_binding=BIND); v8.commit(gg)
held = len(s8)
time.sleep(1.2); s8.prune()
check("the store returns to empty once the window elapses", len(s8) == 0)
check("it held entries while they were live", held > 0)
check("stats() reports a bounded footprint", s8.stats()["bytes_on_disk"] < 8192)
s8.close()

d8 = tempfile.mkdtemp()
path8 = os.path.join(d8, "n.log")
CODE = textwrap.dedent(f'''
    import sys
    sys.path.insert(0, {os.getcwd()!r})
    from driftcore.verification.nonce_store import ExpiringNonceStore
    from driftcore.verification.signed_permission import (
        Grant, PermissionVerifier, PermissionReplay)
    BIND = PermissionVerifier.bind_action("actuator", "act", {{}})
    s = ExpiringNonceStore({path8!r}, retention_seconds=3600,
                           max_grant_ttl_seconds=300)
    v = PermissionVerifier(used_nonces=s); v.register_key("k", "secret", unrestricted=True)
    g = Grant.issue("secret", key_id="k", role="operator", scope=("s:x",),
                    subject="p", ttl_seconds=300, nonce="cross-proc",
                    action_binding=BIND)
    if sys.argv[1] == "burn":
        v.reserve(g, required_scope=("s:x",), action_binding=BIND); v.commit(g); print("BURNED")
    else:
        try:
            v.verify(g, required_scope=("s:x",), action_binding=BIND); print("ACCEPTED")
        except PermissionReplay:
            print("REFUSED")
    s.close()
''')
r1 = subprocess.run([sys.executable, "-c", CODE, "burn"], capture_output=True, text=True)
r2 = subprocess.run([sys.executable, "-c", CODE, "replay"], capture_output=True, text=True)
check("nonce burned in a process that then exited", "BURNED" in r1.stdout)
check("a SEPARATE process refuses the replay (durable across process death)",
      "REFUSED" in r2.stdout)


print("=== self red-team (B2/B5/B6/B10): attacks on the N1-N7 fixes themselves ===")


def _opens(path, **kw):
    """Does the store open, and is `probe` still remembered?"""
    try:
        s = ExpiringNonceStore(path, **kw)
        return s
    except Exception:
        return None


# B2: deleting the .hw sidecar must not erase the rollback guard.
clk_b = {"t": 9000.0}
db = tempfile.mkdtemp(); pb = os.path.join(db, "n.log")
kwb = dict(retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10)
sb = ExpiringNonceStore(pb, time_fn=lambda: clk_b["t"], **kwb)
sb.add("anchor"); sb.close()
os.remove(pb + ".hw")
clk_b["t"] = 8000.0                      # rollback with the sidecar gone
raised = False
try:
    ExpiringNonceStore(pb, time_fn=lambda: clk_b["t"], **kwb).close()
except ClockWentBackwards:
    raised = True
check("B2: deleting the .hw sidecar does NOT erase the rollback guard", raised)

# B10: a poisoned .hw must not brick the store forever.
d10 = tempfile.mkdtemp()
s10 = store_at(d10); s10.add("keep-me"); s10.close()
with open(os.path.join(d10, "n.log") + ".hw", "w") as f:
    f.write("99999999999.0")
s10b = _opens(os.path.join(d10, "n.log"), retention_seconds=3600,
              max_grant_ttl_seconds=300)
check("B10: a poisoned high-water sidecar does not permanently brick the store",
      s10b is not None)
check("B10: and the spent nonce is still remembered", s10b is not None and "keep-me" in s10b)
if s10b:
    s10b.close()

# B6: a far-future record must not become a permanent, never-pruning entry.
d6b = tempfile.mkdtemp()
s6 = store_at(d6b); s6.add("real-one"); s6.close()
with open(os.path.join(d6b, "n.log"), "a") as f:
    f.write("99999999999.0\tFUTURE\n")
s6b = _opens(os.path.join(d6b, "n.log"), retention_seconds=3600,
             max_grant_ttl_seconds=300)
check("B6: a future-dated record does not brick the store", s6b is not None)
check("B6: the legitimate record is intact", s6b is not None and "real-one" in s6b)
if s6b:
    s6b.close()

# B5: a torn trailing append (crash mid-write) must not be read as a whole record.
d5b = tempfile.mkdtemp()
s5 = store_at(d5b); s5.add("committed"); s5.close()
with open(os.path.join(d5b, "n.log"), "a") as f:
    f.write("1786470000.0\tTORN-NO-NEWLINE")      # no trailing newline
s5b = store_at(d5b)
check("B5: a torn trailing record is discarded, not silently accepted",
      "TORN-NO-NEWLINE" not in s5b)
check("B5: committed records before the tear are preserved", "committed" in s5b)
s5b.close()

# and the guard still does its job on a real rollback
clk_r = {"t": 5000.0}
dr = tempfile.mkdtemp(); pr = os.path.join(dr, "n.log")
sr = ExpiringNonceStore(pr, time_fn=lambda: clk_r["t"], **kwb)
sr.add("r"); sr.close()
clk_r["t"] = 4000.0
raised = False
try:
    ExpiringNonceStore(pr, time_fn=lambda: clk_r["t"], **kwb).close()
except ClockWentBackwards:
    raised = True
check("the rollback guard still REFUSES a genuine backwards jump", raised)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
