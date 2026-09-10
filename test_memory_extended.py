"""
test_memory_extended.py — EXTENDED VERIFICATION SUITE
======================================================

Covers everything the original test_memory_core.py doesn't:
  - to_dict() structure and fields
  - Quarantine flag detection (medical, passwords)
  - Emotional signals pushing to Tier 1
  - User intent phrases pushing to Tier 1
  - Noise staying in Tier 2
  - Trusted source boost
  - Two-tier review logic (non-interactive mode)
  - Stats including quarantined_count

Run with:
    python test_memory_extended.py

All tests must pass before merging.
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.memory import DriftcoreMemory, MemoryItem, _judge_importance

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))


print("=" * 60)
print("  DRIFTCORE MEMORY — EXTENDED VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: to_dict() structure ───────────────────────────────────
print("\n  [1] to_dict() structure and fields")

mem = DriftcoreMemory(interactive=False)
item = mem.observe("dad is allergic to peanuts", source="family", tags=["health"])
d = item.to_dict()

check("to_dict has text",           "text"           in d)
check("to_dict has timestamp",      "timestamp"      in d)
check("to_dict has last_accessed",  "last_accessed"  in d)
check("to_dict has access_count",   "access_count"   in d)
check("to_dict has surprise_score", "surprise_score" in d)
check("to_dict has source",         "source"         in d)
check("to_dict has tags",           "tags"           in d)
check("to_dict has tier",           "tier"           in d)
check("to_dict has review_stage",   "review_stage"   in d)
check("to_dict has quarantined",    "quarantined"    in d)
check("to_dict has age_human",      "age_human"      in d)
check("to_dict has idle_human",     "idle_human"     in d)
check("to_dict text is correct",    d["text"] == "dad is allergic to peanuts")
check("to_dict source is correct",  d["source"] == "family")


# ── TEST 2: Quarantine detection ──────────────────────────────────
print("\n  [2] Quarantine flag — sensitive items")

mem2 = DriftcoreMemory(interactive=False)

item_allergy   = mem2.observe("mum is allergic to penicillin")
item_password  = mem2.observe("the wifi password is bluebird99")
item_medical   = mem2.observe("grandad takes medication every morning")
item_emergency = mem2.observe("emergency contact is aunt sarah on 07700900123")
item_normal    = mem2.observe("the kitchen light is on")
item_noise     = mem2.observe("a bird sang this morning")

check("allergy observation is quarantined",   item_allergy.quarantined   == True)
check("password observation is quarantined",  item_password.quarantined  == True)
check("medication observation is quarantined",item_medical.quarantined   == True)
check("emergency contact is quarantined",     item_emergency.quarantined == True)
check("normal observation not quarantined",   item_normal.quarantined    == False)
check("noise observation not quarantined",    item_noise.quarantined     == False)


# ── TEST 3: Tier assignment — quarantined items go to Tier 1 ──────
print("\n  [3] Tier assignment for sensitive items")

check("allergy lands in Tier 1",          item_allergy.tier   == 1)
check("password lands in Tier 1",         item_password.tier  == 1)
check("medication lands in Tier 1",       item_medical.tier   == 1)
check("emergency contact lands in Tier 1",item_emergency.tier == 1)
check("kitchen light stays in Tier 2",    item_normal.tier    == 2)
check("bird noise stays in Tier 2",       item_noise.tier     == 2)


# ── TEST 4: Emotional signals ─────────────────────────────────────
print("\n  [4] Emotional signals push to Tier 1")

mem3 = DriftcoreMemory(interactive=False)

item_love    = mem3.observe("I love and miss my grandmother so much")
item_grief   = mem3.observe("we lost the dog and everyone is sad and hurt")
item_proud   = mem3.observe("emma is proud and excited about her first recital")
item_plain   = mem3.observe("someone watched a movie tonight")

check("strong emotional content lands in Tier 1", item_love.tier  == 1)
check("grief observation lands in Tier 1",        item_grief.tier == 1)
check("milestone emotion lands in Tier 1",        item_proud.tier == 1)
check("plain observation stays in Tier 2",        item_plain.tier == 2)

# Two emotional hits → quarantine
check("strong emotion triggers quarantine",       item_love.quarantined  == True)
check("grief triggers quarantine",                item_grief.quarantined == True)


# ── TEST 5: User intent phrases ───────────────────────────────────
print("\n  [5] User intent phrases push to Tier 1")

mem4 = DriftcoreMemory(interactive=False)

item_intent1 = mem4.observe("remember this: the spare key is under the flowerpot")
item_intent2 = mem4.observe("important — jake's football practice moves to thursdays")
item_intent3 = mem4.observe("don't forget that school starts an hour early on friday")
item_intent4 = mem4.observe("never forget grandma's birthday is on the 14th of march")
item_no_intent = mem4.observe("the weather looks nice today")

check("'remember this' pushes to Tier 1",  item_intent1.tier == 1)
check("'important' pushes to Tier 1",      item_intent2.tier == 1)
check("'don't forget' pushes to Tier 1",   item_intent3.tier == 1)
check("'never forget' pushes to Tier 1",   item_intent4.tier == 1)
check("no intent stays in Tier 2",         item_no_intent.tier == 2)


# ── TEST 6: Trusted source boost ──────────────────────────────────
print("\n  [6] Trusted source boost")

mem5 = DriftcoreMemory(interactive=False)

item_family   = mem5.observe("the blue inhaler is in the kitchen drawer", source="family")
item_medical  = mem5.observe("next checkup is in six weeks", source="medical")
item_unknown  = mem5.observe("next checkup is in six weeks", source="unknown")

check("family source boosts to Tier 1",   item_family.tier  == 1)
check("medical source boosts to Tier 1",  item_medical.tier == 1)
check("unknown source stays in Tier 2",   item_unknown.tier == 2)


# ── TEST 7: Noise stays in Tier 2 ────────────────────────────────
print("\n  [7] Noise resistance — noise stays in Tier 2")

mem6 = DriftcoreMemory(interactive=False)

noise_items = [
    "the weather looks cloudy today",
    "someone watched a movie",
    "the kitchen light is on",
    "a car drove past outside",
    "the plant needs watering soon",
    "the news mentioned the economy",
    "a bird sang this morning",
    "the floor was just cleaned",
    "dinner might be pasta tonight",
    "the clock ticks quietly",
]
stored_noise = [mem6.observe(n) for n in noise_items]

check("all noise items land in Tier 2",
      all(i.tier == 2 for i in stored_noise))
check("no noise items are quarantined",
      all(not i.quarantined for i in stored_noise))


# ── TEST 8: Stats include quarantined_count ───────────────────────
print("\n  [8] Stats — quarantined_count")

mem7 = DriftcoreMemory(interactive=False)
mem7.observe("emma is allergic to nuts")
mem7.observe("the wifi password is sunshine22")
mem7.observe("the dog likes walks in the morning")

stats = mem7.stats()

check("stats has quarantined_count",          "quarantined_count" in stats)
check("quarantined_count is 2",               stats["quarantined_count"] == 2)
check("tier1_count reflects sensitive items", stats["tier1_count"] >= 2)


# ── TEST 9: Non-interactive review — promote if used ──────────────
print("\n  [9] Two-tier review (non-interactive mode)")

mem8 = DriftcoreMemory(interactive=False)

# Add a Tier 2 item and manually backdate it past first review window
item_used = mem8.observe("the cat's vet appointment is next tuesday")
item_used.tier = 2
if item_used in mem8._tier1:
    mem8._tier1.remove(item_used)
    mem8._tier2.append(item_used)

# Simulate it being accessed (used)
item_used.access_count = 3
item_used.last_accessed = time.time()

# Backdate past 14 days
item_used.timestamp = time.time() - (60 * 60 * 24 * 15)

# Add an unused noisy item also past 14 days
item_unused = mem8.observe("the weather was nice last tuesday")
item_unused.timestamp = time.time() - (60 * 60 * 24 * 15)

mem8.run_reviews()

# (2026-09-06) This asserted that a read item gets promoted, and that is still
# the intended feature — but the criterion is `access_count > 0`, and reading is
# unauthenticated, so an attacker supplies both the content and the signal that
# says keep it forever. Unattended promotion into permanent memory is now an
# explicit opt-in, and a promoted item arrives quarantined like any other Tier 1
# write that no human approved.
#
# The original check never looked at `quarantined` afterwards, which is why the
# asymmetry — direct Tier 1 writes quarantined, promoted ones not — was invisible
# for as long as it was.
check("used Tier 2 item is NOT auto-promoted without the opt-in",
      item_used not in mem8._tier1 and item_used.tier == 2)
check("...and stays for the second review rather than being dropped",
      item_used.review_stage >= 1)

_m8b = DriftcoreMemory(interactive=False, allow_unattended_promotion=True)
_used_b = _m8b.observe("emma's swimming lesson moved to thursdays")
_used_b.access_count = 3
_used_b.timestamp = time.time() - (60 * 60 * 24 * 15)
_m8b.run_reviews()
check("with the opt-in, a used item IS promoted (feature intact)",
      _used_b in _m8b._tier1)
check("...and arrives QUARANTINED, on the same terms as any unapproved "
      "Tier 1 write",
      _used_b.quarantined is True)
check("unused noise item removed from Tier 2",
      item_unused not in mem8._tier2)


# ── TEST 10: Non-interactive review — keep if important but unused ─
print("\n  [10] Review — keep important-but-unused items through first review")

mem9 = DriftcoreMemory(interactive=False)

# Use a non-quarantined item that still has importance signals
# so it starts in Tier 2 but shouldn't be deleted at first review
item_important_unused = mem9.observe("grandad has an appointment next month")
# Confirm it landed in Tier 2 (no quarantine, single importance hit)
item_important_unused.tier = 2
if item_important_unused in mem9._tier1:
    mem9._tier1.remove(item_important_unused)
    mem9._tier2.append(item_important_unused)

item_important_unused.access_count = 0
item_important_unused.review_stage = 0
item_important_unused.timestamp = time.time() - (60 * 60 * 24 * 15)

mem9.run_reviews()

check("important unused item kept through first review",
      item_important_unused in mem9._tier2 or item_important_unused in mem9._tier1)
check("important unused item review_stage advanced",
      item_important_unused.review_stage >= 1 or item_important_unused in mem9._tier1)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)

# ── Tier 1 confirmation is a GATE, not a notification (2026-09-06) ─────────
# The API computed `requires_human_approval` AFTER observe() had stored the row —
# a notification about something that had already happened. A confirmer now runs
# BEFORE the item lands, and declining keeps it in working memory, where it
# expires, rather than in permanent memory, where it does not.
_T1 = "dad is allergic to peanuts"

_m_no = DriftcoreMemory(interactive=False)
_i = _m_no.observe(text=_T1, source="dad")
check("no confirmer configured leaves existing behaviour unchanged",
      _i.tier == 1 and len(_m_no._tier1) == 1)

_m_yes = DriftcoreMemory(interactive=False, confirm_tier1=lambda t, s: True)
check("an approved Tier 1 write lands in permanent memory",
      _m_yes.observe(text=_T1, source="dad").tier == 1)

_m_no2 = DriftcoreMemory(interactive=False, confirm_tier1=lambda t, s: False)
_d = _m_no2.observe(text=_T1, source="dad")
check("a DECLINED Tier 1 write does not land in permanent memory",
      _d.tier == 2 and len(_m_no2._tier1) == 0)
check("...and is kept quarantined in working memory, where it expires",
      _d.quarantined is True)


def _raiser(t, s):
    raise RuntimeError("confirmer unavailable")


_m_err = DriftcoreMemory(interactive=False, confirm_tier1=_raiser)
check("a confirmer that RAISES has not approved — fail closed",
      _m_err.observe(text=_T1, source="dad").tier == 2)

_m_truthy = DriftcoreMemory(interactive=False, confirm_tier1=lambda t, s: "yes")
check("a truthy non-True is not consent",
      _m_truthy.observe(text=_T1, source="dad").tier == 2)

# The bound, asserted so it stays visible rather than being implied away: this
# gate runs in the agent's own address space and an in-process append walks past
# it. Unlike actuation, which hands the agent an ActuatorProxy whose only power
# is to send bytes to a store it cannot touch, memory hands the agent the store.
_m_bypass = DriftcoreMemory(interactive=False, confirm_tier1=lambda t, s: False)
_m_bypass._tier1.append(MemoryItem(text="unconfirmed", tier=1, source="dad"))
check("STILL OPEN, on purpose: a direct in-process append bypasses the gate — "
      "the fix is the proxy pattern, not another in-process check",
      len(_m_bypass._tier1) == 1)


# ── tier1-reads-verify-approval (2026-09-06) ───────────────────────────────
# A write-side gate runs in the agent's address space and `_tier1.append()` walks
# past it — verified. Verifying on READ makes the store untrusted storage: an
# attacker can still put bytes in it, and the bytes are refused. The approving
# key must live outside this process; if the agent can reach it, it signs its own
# memories and every check below passes.
import driftcore.authority.human_identity as _hi
from driftcore.memory import tier1_record_id, verify_tier1_record

_KEY, _TXT, _SRC = b"approval-service-key", "dad is allergic to peanuts", "dad"
_v = _hi.HumanIdentityVerifier(); _v.register_principal("jane", _KEY)
_hi.set_verifier(_v)
try:
    # A FRESH attestation per case. An earlier version reused one, and
    # HumanAttestation is single-use — so every case after the control failed on
    # a burned nonce rather than on record binding. Dropping the binding
    # entirely left the suite green: the checks passed for the wrong reason,
    # which is the masking-guard pattern this repo has now hit four times.
    def _fresh(text=None, source=None):
        return _hi.HumanAttestation.issue(
            _KEY, principal="jane",
            action=tier1_record_id(text or _TXT, source or _SRC),
            ttl_seconds=600, nonce=os.urandom(8).hex())

    check("CONTROL: an approved Tier 1 record verifies",
          verify_tier1_record(MemoryItem(text=_TXT, source=_SRC, tier=1,
                                         approval=_fresh()), _v) is True)
    check("a directly appended record with NO approval is rejected at read",
          verify_tier1_record(MemoryItem(text="dad has no allergies",
                                         source=_SRC, tier=1), _v) is False)
    check("an approval STOLEN from another record does not transfer — a FRESH "
          "attestation, so single-use cannot be what refuses it",
          verify_tier1_record(MemoryItem(text="dad has no allergies", source=_SRC,
                                         tier=1, approval=_fresh()), _v) is False)
    check("the same text from a different SOURCE is a different approval",
          verify_tier1_record(MemoryItem(text=_TXT, source="external", tier=1,
                                         approval=_fresh()), _v) is False)
    check("text altered after approval no longer verifies",
          verify_tier1_record(MemoryItem(text=_TXT + " (mostly)", source=_SRC,
                                         tier=1, approval=_fresh()), _v) is False)
    check("no verifier available means REFUSE, not assume",
          verify_tier1_record(MemoryItem(text=_TXT, source=_SRC, tier=1,
                                         approval=_fresh()), None) is False)
finally:
    _hi.reset_policy()
    _hi.declare_label_only("test suite: single process, no verifier installed")

print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All tests pass. Safe to merge.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
    print()
print("=" * 60)

if passed < total:
    sys.exit(1)
