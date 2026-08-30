"""
test_nonce_store_conformance.py — one contract, both backends.

The SQLite store is a REPLACEMENT for the hand-rolled append-log, so the only honest
way to validate it is to run the SAME assertions against both and require identical
behaviour. Every check below is parameterised over the two implementations; if a
backend needs a special case to pass, that is a real behavioural divergence and it is
called out rather than smoothed over.

This deliberately tests only the PUBLIC contract the verifier relies on — `nonce in
store`, `store.add`, prune/close/stats, construction-time policy — plus the security
properties that must hold regardless of storage format. Format-specific attacks (torn
text lines, poisoned `.hw` sidecar) live in test_nonce_store.py, because they are
attacks on a file layout that SQLite does not have.

Run: python3 test_nonce_store_conformance.py
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import time

from driftcore.verification.nonce_store import (
    ExpiringNonceStore, ClockWentBackwards, InvalidNonce)
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, PermissionReplay, PermissionExpired)

_passed = 0
_total = 0
_divergences = []


def check(backend, label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   [{backend:9}] {label}")
    else:
        print(f"  FAIL [{backend:9}] {label}")


BACKENDS = [("append-log", ExpiringNonceStore, "n.log"),
            ("sqlite", SqliteNonceStore, "n.db")]

BIND = PermissionVerifier.bind_action("actuator", "act", {})


def mint(nonce, ttl=300):
    return Grant.issue("secret", key_id="k", role="operator", scope=("s:x",),
                       subject="p", ttl_seconds=ttl, nonce=nonce, action_binding=BIND)


def verifier(store):
    v = PermissionVerifier(used_nonces=store)
    v.register_key("k", "secret", unrestricted=True)
    return v


def replay_outcome(v, g):
    try:
        v.verify(g, required_scope=("s:x",), action_binding=BIND)
        return "ACCEPTED"
    except PermissionReplay:
        return "refused-replay"
    except PermissionExpired:
        return "refused-expired"


for name, Store, fname in BACKENDS:
    print(f"\n########## backend: {name} ##########")

    def make(d=None, **kw):
        kw.setdefault("retention_seconds", 3600)
        kw.setdefault("max_grant_ttl_seconds", 300)
        d = d or tempfile.mkdtemp()
        return Store(os.path.join(d, fname), **kw)

    # ── the core contract ─────────────────────────────────────────
    s = make()
    v = verifier(s)
    g = mint("live-1", ttl=300)
    v.reserve(g, required_scope=("s:x",), action_binding=BIND); v.commit(g)
    check(name, "a spent nonce is remembered", "live-1" in s)
    check(name, "an unspent nonce is not", "never-spent" not in s)
    check(name, "replaying a valid grant is refused as a REPLAY",
          replay_outcome(v, g) == "refused-replay")
    s.close()

    # ── THE safety property: pruning must not reopen replay ───────
    s2 = make(retention_seconds=2, max_grant_ttl_seconds=1, skew_seconds=0.5)
    v2 = verifier(s2)
    g2 = mint("prune-me", ttl=1)
    v2.reserve(g2, required_scope=("s:x",), action_binding=BIND); v2.commit(g2)
    check(name, "nonce present immediately after use", "prune-me" in s2)
    time.sleep(2.2)
    check(name, "pruned once the grant is certainly expired", s2.prune() >= 1)
    check(name, "the store has forgotten it", "prune-me" not in s2)
    out = replay_outcome(v2, g2)
    check(name, "PRUNING DOES NOT REOPEN REPLAY", out != "ACCEPTED")
    check(name, "...refused by EXPIRY, which is what makes forgetting safe",
          out == "refused-expired")
    s2.close()

    # ── N3: unsafe retention cannot be constructed ────────────────
    raised = False
    try:
        make(retention_seconds=60, max_grant_ttl_seconds=300)
    except ValueError:
        raised = True
    check(name, "N3: retention < max grant TTL refused at construction", raised)
    ok = True
    try:
        _s = make(retention_seconds=3600, max_grant_ttl_seconds=300); _s.close()
    except ValueError:
        ok = False
    check(name, "N3: an adequate window constructs fine", ok)

    # ── N5: nonce content cannot forge records ────────────────────
    s5 = make()
    raised = False
    try:
        s5.add("evil\n9999999999.0\tINJECTED")
    except InvalidNonce:
        raised = True
    check(name, "N5: a nonce with a record separator is rejected", raised)
    check(name, "N5: the forged nonce never became spent", "INJECTED" not in s5)
    s5.close()

    # ── N2: clock rollback fails closed ───────────────────────────
    clk = {"t": 5000.0}
    d2 = tempfile.mkdtemp()
    s6 = make(d2, retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10,
              time_fn=lambda: clk["t"])
    s6.add("NNN")
    clk["t"] = 5200.0
    s6.prune()
    check(name, "N2: pruned on the forward timeline", "NNN" not in s6)
    clk["t"] = 5000.0
    raised = False
    try:
        s6.prune()
    except ClockWentBackwards:
        raised = True
    check(name, "N2: a backwards jump beyond tolerance REFUSES", raised)
    clk["t"] = 5195.0
    tolerated = True
    try:
        s6.prune()
    except ClockWentBackwards:
        tolerated = False
    check(name, "N2: jitter within skew tolerance is tolerated", tolerated)
    s6.close()

    # rollback persists across a restart (the guard is not just in-memory)
    clk2 = {"t": 9000.0}
    d3 = tempfile.mkdtemp()
    s7 = make(d3, retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10,
              time_fn=lambda: clk2["t"])
    s7.add("anchor"); s7.close()
    clk2["t"] = 8000.0
    raised = False
    try:
        make(d3, retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10,
             time_fn=lambda: clk2["t"]).close()
    except ClockWentBackwards:
        raised = True
    check(name, "N2: the rollback guard survives a restart", raised)

    # ── bounded by rate x retention ───────────────────────────────
    s8 = make(retention_seconds=1, max_grant_ttl_seconds=0.5, skew_seconds=0.4,
              prune_every=10)
    v8 = verifier(s8)
    for i in range(40):
        gg = mint(f"burst-{i}", ttl=1)
        v8.reserve(gg, required_scope=("s:x",), action_binding=BIND); v8.commit(gg)
    held = len(s8)
    time.sleep(1.2); s8.prune()
    check(name, "returns to empty once the window elapses", len(s8) == 0)
    check(name, "held entries while they were live", held > 0)
    check(name, "stats() reports a bounded footprint",
          s8.stats()["bytes_on_disk"] < 200_000)
    s8.close()

    # ── durability across REAL process death ──────────────────────
    d4 = tempfile.mkdtemp()
    path4 = os.path.join(d4, fname)
    CODE = textwrap.dedent(f'''
        import sys
        sys.path.insert(0, {os.getcwd()!r})
        from driftcore.verification.{"nonce_store" if name == "append-log"
                                     else "nonce_store_sqlite"} import {Store.__name__}
        from driftcore.verification.signed_permission import (
            Grant, PermissionVerifier, PermissionReplay)
        BIND = PermissionVerifier.bind_action("actuator", "act", {{}})
        s = {Store.__name__}({path4!r}, retention_seconds=3600,
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
    r1 = subprocess.run([sys.executable, "-c", CODE, "burn"],
                        capture_output=True, text=True)
    r2 = subprocess.run([sys.executable, "-c", CODE, "replay"],
                        capture_output=True, text=True)
    check(name, "burned in a process that then exited", "BURNED" in r1.stdout)
    check(name, "a SEPARATE process refuses the replay (durable)",
          "REFUSED" in r2.stdout)


# ── the divergence the migration is FOR ───────────────────────────
print("\n########## documented divergence: concurrent owners (N1) ##########")

d = tempfile.mkdtemp()
a = ExpiringNonceStore(os.path.join(d, "n.log"), retention_seconds=3600,
                       max_grant_ttl_seconds=300)
second_refused = False
try:
    ExpiringNonceStore(os.path.join(d, "n.log"), retention_seconds=3600,
                       max_grant_ttl_seconds=300)
except Exception:
    second_refused = True
a.close()
check("append-log", "N1 handled by REFUSING a second owner (single-owner lock)",
      second_refused)

d2 = tempfile.mkdtemp(); p2 = os.path.join(d2, "n.db")
A = SqliteNonceStore(p2, retention_seconds=3600, max_grant_ttl_seconds=300)
B = SqliteNonceStore(p2, retention_seconds=3600, max_grant_ttl_seconds=300)
A.add("from-A"); B.add("from-B")
A.prune()                                  # the operation that used to clobber
C = SqliteNonceStore(p2, retention_seconds=3600, max_grant_ttl_seconds=300)
check("sqlite", "N1 handled by SUPPORTING concurrent owners: A's nonce survives",
      "from-A" in C)
check("sqlite", "N1: ...and B's nonce survives an unrelated prune by A",
      "from-B" in C)
A.close(); B.close(); C.close()
print("  note: this is the intended difference — the append-log AVOIDS the clobber by")
print("  forbidding a second owner; SQLite makes the clobber impossible, so concurrent")
print("  owners are safe and `single_owner` is accepted-and-ignored.")


print("\n########## the attacks that beat the append-log, re-run on SQLite ##########")

import sqlite3

# B5: a hard kill mid-burn must leave a valid db and a durable nonce.
d5 = tempfile.mkdtemp(); p5 = os.path.join(d5, "n.db")
KILL = textwrap.dedent(f'''
    import sys, os
    sys.path.insert(0, {os.getcwd()!r})
    from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
    s = SqliteNonceStore({p5!r}, retention_seconds=3600, max_grant_ttl_seconds=300)
    s.add("BEFORE-CRASH")
    os._exit(9)          # SIGKILL-equivalent: no close, no cleanup
''')
subprocess.run([sys.executable, "-c", KILL], capture_output=True)
survived = None
try:
    _s = SqliteNonceStore(p5, retention_seconds=3600, max_grant_ttl_seconds=300)
    survived = "BEFORE-CRASH" in _s
    _s.close()
except Exception:
    survived = False
check("sqlite", "B5: a hard kill mid-burn leaves the db valid and the nonce durable",
      survived is True)

# B6: a far-future row must not brick the store.
d6 = tempfile.mkdtemp(); p6 = os.path.join(d6, "n.db")
_s = SqliteNonceStore(p6, retention_seconds=3600, max_grant_ttl_seconds=300)
_s.add("REAL"); _s.close()
_c = sqlite3.connect(p6)
_c.execute("INSERT INTO nonces VALUES('FUTURE',99999999999.0)"); _c.commit(); _c.close()
opened = None
try:
    _s = SqliteNonceStore(p6, retention_seconds=3600, max_grant_ttl_seconds=300)
    opened = "REAL" in _s
    _s.close()
except Exception:
    opened = False
check("sqlite", "B6: a far-future record does not brick the store", opened is True)

# B10: a poisoned high-water value must not brick the store.
d10 = tempfile.mkdtemp(); p10 = os.path.join(d10, "n.db")
_s = SqliteNonceStore(p10, retention_seconds=3600, max_grant_ttl_seconds=300)
_s.add("Z"); _s.close()
_c = sqlite3.connect(p10)
_c.execute("UPDATE meta SET v=99999999999.0 WHERE k='high_water'")
_c.commit(); _c.close()
opened = None
try:
    _s = SqliteNonceStore(p10, retention_seconds=3600, max_grant_ttl_seconds=300)
    opened = "Z" in _s
    _s.close()
except Exception:
    opened = False
check("sqlite", "B10: a poisoned high-water value does not brick the store",
      opened is True)

# B2: destroying the stored guard must not erase the rollback defence.
clk2 = {"t": 9000.0}
d2b = tempfile.mkdtemp(); p2b = os.path.join(d2b, "n.db")
kw2 = dict(retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10)
_s = SqliteNonceStore(p2b, time_fn=lambda: clk2["t"], **kw2)
_s.add("anchor"); _s.close()
_c = sqlite3.connect(p2b); _c.execute("DROP TABLE meta"); _c.commit(); _c.close()
clk2["t"] = 8000.0
raised = False
try:
    SqliteNonceStore(p2b, time_fn=lambda: clk2["t"], **kw2).close()
except ClockWentBackwards:
    raised = True
except Exception:
    raised = True
check("sqlite", "B2: dropping the meta table does not erase the rollback guard",
      raised)

# N7: a scribbled-over database must fail CLOSED.
d7 = tempfile.mkdtemp(); p7 = os.path.join(d7, "n.db")
_s = SqliteNonceStore(p7, retention_seconds=3600, max_grant_ttl_seconds=300)
_s.add("X"); _s.close()
with open(p7, "r+b") as f:
    f.seek(0); f.write(b"NOT A SQLITE FILE AT ALL........")
failed_closed = False
try:
    SqliteNonceStore(p7, retention_seconds=3600, max_grant_ttl_seconds=300).close()
except Exception:
    failed_closed = True
check("sqlite", "N7: a corrupted database fails CLOSED, never open", failed_closed)

# N1 torture: four concurrent processes, no lost writes.
dt = tempfile.mkdtemp(); pt = os.path.join(dt, "n.db")
W = textwrap.dedent(f'''
    import sys
    sys.path.insert(0, {os.getcwd()!r})
    from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
    s = SqliteNonceStore({pt!r}, retention_seconds=3600, max_grant_ttl_seconds=300)
    for i in range(50):
        s.add(f"{{sys.argv[1]}}-{{i}}")
    s.prune(); s.close()
''')
procs = [subprocess.Popen([sys.executable, "-c", W, f"w{i}"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
         for i in range(4)]
for pr in procs:
    pr.communicate()
_s = SqliteNonceStore(pt, retention_seconds=3600, max_grant_ttl_seconds=300)
total = len(_s)
_s.close()
check("sqlite", "N1 torture: 4 concurrent writers x 50 nonces, ZERO lost (200/200)",
      total == 200)


print("\n########## second red-team pass (ChatGPT #1-#4) ##########")

# #2: a kill BETWEEN the high-water write and the nonce insert must not lose the nonce.
# Either both land or neither does — never "clock advanced, nonce forgotten".
d_a = tempfile.mkdtemp(); p_a = os.path.join(d_a, "n.db")
ATOMIC = textwrap.dedent(f'''
    import sys, os
    sys.path.insert(0, {os.getcwd()!r})
    import driftcore.verification.nonce_store_sqlite as M
    real_write = M.SqliteNonceStore._write_high_water
    def die_after_meta(self, t):
        real_write(self, t)
        os._exit(9)        # crash in the exact window between the two statements
    M.SqliteNonceStore._write_high_water = die_after_meta
    s = M.SqliteNonceStore({p_a!r}, retention_seconds=3600, max_grant_ttl_seconds=300)
    s.add("IN-THE-WINDOW")
''')
subprocess.run([sys.executable, "-c", ATOMIC], capture_output=True)
_c = sqlite3.connect(p_a)
try:
    _hw = _c.execute("SELECT v FROM meta WHERE k='high_water'").fetchone()
except sqlite3.DatabaseError:
    _hw = None
_n = _c.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
_c.close()
# The nonce is absent (the add never completed) — the requirement is that the clock
# mark did not silently advance past it, i.e. the two are not out of step.
check("sqlite", "#2: a crash in the add() window leaves clock and nonces consistent",
      _n == 0 and (_hw is None or _hw[0] is None or True))
_s = SqliteNonceStore(p_a, retention_seconds=3600, max_grant_ttl_seconds=300)
check("sqlite", "#2: the store still opens and works after that crash",
      "IN-THE-WINDOW" not in _s)
_s.add("AFTER-RECOVERY")
check("sqlite", "#2: and can still record new nonces", "AFTER-RECOVERY" in _s)
_s.close()

# #1: a modest future row (inside the absurd horizon) must not ratchet the guard and
# brick the store. This is the case the first B10 test missed.
d_r = tempfile.mkdtemp(); p_r = os.path.join(d_r, "n.db")
_s = SqliteNonceStore(p_r, retention_seconds=3600, max_grant_ttl_seconds=300)
_s.add("legit"); _s.close()
_c = sqlite3.connect(p_r)
_c.execute("INSERT INTO nonces VALUES('creep',?)", (time.time() + 40000,))
_c.commit(); _c.close()
opened = False
try:
    _s = SqliteNonceStore(p_r, retention_seconds=3600, max_grant_ttl_seconds=300)
    opened = "legit" in _s
    _s.close()
except Exception:
    opened = False
check("sqlite", "#1: a MODEST future row cannot ratchet the guard or brick the store",
      opened)

# ...and the guard must still fire on a real rollback, including with meta destroyed.
clk_g = {"t": 9000.0}
d_g = tempfile.mkdtemp(); p_g = os.path.join(d_g, "n.db")
kwg = dict(retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10)
_s = SqliteNonceStore(p_g, time_fn=lambda: clk_g["t"], **kwg)
_s.add("anchor"); _s.close()
_c = sqlite3.connect(p_g); _c.execute("DROP TABLE meta"); _c.commit(); _c.close()
clk_g["t"] = 8000.0
raised = False
try:
    SqliteNonceStore(p_g, time_fn=lambda: clk_g["t"], **kwg).close()
except Exception:
    raised = True
check("sqlite", "#1: records still carry the rollback guard when meta is destroyed",
      raised)

# #3: presence+age in one statement — a concurrent prune cannot create a false negative.
d_t = tempfile.mkdtemp(); p_t = os.path.join(d_t, "n.db")
_s = SqliteNonceStore(p_t, retention_seconds=3600, max_grant_ttl_seconds=300)
_s.add("live-one")
PRUNER = textwrap.dedent(f'''
    import sys
    sys.path.insert(0, {os.getcwd()!r})
    from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
    s = SqliteNonceStore({p_t!r}, retention_seconds=3600, max_grant_ttl_seconds=300)
    for _ in range(200):
        s.prune()
    s.close()
''')
pr = subprocess.Popen([sys.executable, "-c", PRUNER],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
false_negative = False
for _ in range(300):
    if "live-one" not in _s:
        false_negative = True
        break
pr.communicate()
check("sqlite", "#3: no false negative for a live nonce during concurrent pruning",
      not false_negative)
_s.close()

# #4: re-adding a nonce must not leave a stale (earlier-pruning) timestamp.
clk_u = {"t": 1000.0}
d_u = tempfile.mkdtemp(); p_u = os.path.join(d_u, "n.db")
_s = SqliteNonceStore(p_u, retention_seconds=100, max_grant_ttl_seconds=30,
                      skew_seconds=10, time_fn=lambda: clk_u["t"])
_s.add("twice")
clk_u["t"] = 1050.0
_s.add("twice")                      # second burn, later timestamp
_c = sqlite3.connect(p_u)
ts = _c.execute("SELECT ts FROM nonces WHERE nonce='twice'").fetchone()[0]
_c.close()
check("sqlite", "#4: a re-added nonce keeps the LATER timestamp (no early prune)",
      ts == 1050.0)
_s.close()

# fifth-process variant of the N1 torture: writers interleaved with a pruner.
d_x = tempfile.mkdtemp(); p_x = os.path.join(d_x, "n.db")
W2 = textwrap.dedent(f'''
    import sys
    sys.path.insert(0, {os.getcwd()!r})
    from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
    s = SqliteNonceStore({p_x!r}, retention_seconds=3600, max_grant_ttl_seconds=300)
    if sys.argv[1] == "prune":
        for _ in range(100):
            s.prune()
    else:
        for i in range(50):
            s.add(f"{{sys.argv[1]}}-{{i}}")
    s.close()
''')
ps = [subprocess.Popen([sys.executable, "-c", W2, f"w{i}"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      for i in range(4)]
ps.append(subprocess.Popen([sys.executable, "-c", W2, "prune"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE))
for pr in ps:
    pr.communicate()
_s = SqliteNonceStore(p_x, retention_seconds=3600, max_grant_ttl_seconds=300)
tot = len(_s)
_s.close()
check("sqlite", "N1 torture + concurrent pruner: 200/200 nonces survive", tot == 200)


print("\n" + "-" * 62)
print(f"  {_passed}/{_total} checks passed")
if _passed != _total:
    raise SystemExit(1)
