"""The signing key does not survive a process restart, so signed state fails
verification on reboot — and fails as TAMPER, not as a graceful error.

`enforcement._SESSION_KEY` is `os.urandom(32)` per process. There is no loader and
no derivation from anything persistent. The ENCRYPTION key is different: it comes
from `derive_key(passphrase)` and is reproducible, so decryption survives a
restart. Integrity has no equivalent path.

The suite cannot see this. Every test file resets `_SESSION_KEY = None` and does
its store and its load inside ONE process, so cross-process persistence is never
exercised anywhere.

Run from the repo root: python3 probes/probe_restart_persistence.py
"""
import os
import subprocess
import sys
import tempfile
import textwrap

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(f"REFUSING TO RUN: no driftcore package at {_root!r}.")

_dir = tempfile.mkdtemp()
os.makedirs(os.path.join(_dir, "data"), exist_ok=True)
_db = os.path.join(_dir, "data", "t.db")


def run(body):
    code = f"import sys; sys.path.insert(0, {_root!r})\n" + textwrap.dedent(body)
    return subprocess.run([sys.executable, "-c", code], cwd=_dir,
                          capture_output=True, text=True, timeout=90)


print("\n[control] store and read in the SAME process — what the suite tests")
same = run(f'''
    import types
    import driftcore.storage as st
    st._ENCRYPTION_KEY = st.derive_key("admin-passphrase")[0]
    st.SecureStorage._tamper_shutdown = lambda self, r: print("TAMPER")
    s = st.SecureStorage({_db + ".same"!r}); s.open()
    s.store_tier1(types.SimpleNamespace(text="persisted fact", source="note",
        timestamp=1., tags=["f"], quarantined=False, surprise_score=.5,
        last_accessed=1., access_count=0, review_stage=0))
    print("read back:", [i.text for i in s.load_tier1()])
''')
print("  " + (same.stdout.strip() or same.stderr.strip()[-120:]))

print("\n[1] store in process A")
a = run(f'''
    import types
    import driftcore.storage as st
    st._ENCRYPTION_KEY = st.derive_key("admin-passphrase")[0]
    s = st.SecureStorage({_db!r}); s.open()
    s.store_tier1(types.SimpleNamespace(text="persisted fact", source="note",
        timestamp=1., tags=["f"], quarantined=False, surprise_score=.5,
        last_accessed=1., access_count=0, review_stage=0))
    print("stored")
''')
print("  " + (a.stdout.strip() or a.stderr.strip()[-120:]))

print("\n[2] read in process B — a restart, with the SAME admin passphrase")
b = run(f'''
    import driftcore.storage as st
    st._ENCRYPTION_KEY = st.derive_key("admin-passphrase")[0]
    st.SecureStorage._tamper_shutdown = lambda self, r: print("TAMPER SHUTDOWN:", r[:80])
    s = st.SecureStorage({_db!r}); s.open()
    print("read back:", [i.text for i in s.load_tier1()])
''')
out = b.stdout.strip() or b.stderr.strip()[-200:]
print("  " + out.replace("\n", "\n  "))

print("\n" + "=" * 70)
tampered = "TAMPER" in out
print(f"  restart reports TAMPER on its own untouched data : {tampered}")
print(f"  records recovered after restart                  : "
      f"{'none' if '[]' in out or tampered else 'some'}")
print()
if tampered:
    print("  The record was not altered. The key that signed it no longer exists.")
    print("  Two consequences, and the second is worse than the first:")
    print("    1. Tier 1 memory does not survive a restart.")
    print("    2. The failure is a TAMPER SHUTDOWN — the 'something is wrong, I")
    print("       need to be fixed' path — so a normal reboot is indistinguishable")
    print("       from an attack, and the alarm that would signal a real one is")
    print("       spent on every restart.")
    print()
    print("  Root cause: enforcement._SESSION_KEY = os.urandom(32), per process,")
    print("  with no loader. Confidentiality has a passphrase-derived path")
    print("  (`derive_key`); integrity does not. Fix shape: derive the signing key")
    print("  from the same admin passphrase, or custody it in _config/ beside the")
    print("  admin credentials. That is a key-custody decision, not a patch.")
