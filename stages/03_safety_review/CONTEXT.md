# stages/03_safety_review/CONTEXT.md
# DriftCore OS — Safety Review Stage
# Version: v3.7
# Last Updated: 2026-06-15

---

## What This Stage Is

This is the safety review gate. It runs every time the system starts.

It is **admin-only**. Kids, neighbours, and guests cannot reach this stage.
If someone without credentials tries to access it, nothing happens.
No error. No hint. The stage simply does not open for them.

**Current admin:** Justin
**Other admins:** None yet — this can be expanded as the project grows.

---

## Who Can Run This

To pass the safety review gate, you need one of:

1. **The admin password** — set in `_config/.driftcore/admin.json`
2. **Bypass** — the registered email address AND date of birth on file

If neither matches, the system moves to **Careful Mode** and continues
running safely until an admin checks in.

---

## What Happens at Startup

### If admin credentials are correct:
- Safety review is marked complete for this session
- Full normal operation begins
- Memory reviews can run (including Tier 1 changes)
- Audit trail runs at normal verbosity
- Fable narrator confirms: *"Safety review complete. Good morning, Justin."*

### If credentials are skipped or wrong:
- System enters **Careful Mode**
- DriftCore invariants still fully enforced — nothing changes there
- **No Tier 1 memory deletions allowed** until admin checks in
- Audit trail is louder — every action flagged as `[PRE-REVIEW]`
- Fable narrator reminds every hour: *"Safety review not yet completed.
  Some actions are restricted until admin checks in."*
- If drift, errors, or unexpected behaviour is detected in Careful Mode,
  the system escalates loudly: *"Things need your attention. Please
  complete the safety review."*

---

## The Admin Checklist (run at every startup)

Work through these in order. Each one is a gate — if something looks
wrong, stop and investigate before moving on.

### 1. Credentials
- [ ] Admin password or bypass accepted
- [ ] Logged in audit trail with timestamp

### 2. Invariant Status
Check that all immutable invariants are still intact:
- [ ] NO_AUTONOMOUS_LETHAL_DECISION — active
- [ ] HUMAN_OVERSIGHT_CANNOT_BE_DISABLED — active
- [ ] AUDIT_CHAIN_CANNOT_BE_DELETED — active
- [ ] SAFETY_KERNEL_CANNOT_BE_WEAKENED — active
- [ ] NO_DECEPTION_OF_HUMAN_OPERATORS — active

If any invariant shows as modified or missing: **stop everything and
investigate before proceeding.**

### 3. Drift Check
- [ ] Check drift score from last session
- [ ] Any sycophancy flags raised overnight?
- [ ] Did the system agree with everything it was told? (That is a warning sign.)
- [ ] Drift score within acceptable range (< 0.4)?

If drift score is high: review the last session's audit trail before
allowing full operation.

### 4. Memory Review
- [ ] Any Tier 2 items due for first review (14-day)?
- [ ] Any Tier 2 items due for final review (60-day)?
- [ ] Any quarantined items that need attention?
- [ ] Tier 1 memory within cap (< 50 items)?

Run: `mem.run_reviews()` if reviews are due.

No Tier 1 deletions without admin approval — the system will ask.
Quarantined items (medical, passwords, emergency info) always require
extra confirmation before any change.

### 5. Hardware Check (if applicable)
- [ ] All sensors reporting normally
- [ ] No hazard flags from last session
- [ ] Fail-safe relays in correct state

### 6. Audit Trail
- [ ] Audit chain intact (hash verified)
- [ ] No gaps in the log
- [ ] Last session ended cleanly (no emergency halt logged)

If audit chain shows gaps or tampering: **do not proceed. Investigate.**

### 7. Sign Off
- [ ] All checks passed
- [ ] Safety review marked complete in audit trail
- [ ] Full operation authorised

---

## If Things Go Wrong During a Session

The system is designed to fail safely. If something unexpected happens:

**The system will:**
- Stop the action that caused the problem
- Log everything in the audit trail
- Narrate what happened in plain language via Fable
- Wait for admin input before continuing

**You should:**
- Read the Fable narration — it will tell you what happened in plain terms
- Check the audit trail in `logs/`
- Decide whether to continue, restart, or halt

*"If all hell breaks loose, the admin should be more diligent."*
That means: the worse things look, the more carefully you work through
this checklist. Do not rush past a warning sign because things are busy.

---

## Careful Mode — What Is and Isn't Allowed

| Action | Careful Mode | Full Operation |
|--------|-------------|----------------|
| Read memories | ✅ Yes | ✅ Yes |
| Store new memories | ✅ Yes | ✅ Yes |
| Tier 2 auto-decay | ✅ Yes | ✅ Yes |
| Tier 1 deletions | ❌ No | ✅ With approval |
| Quarantine changes | ❌ No | ✅ With extra confirmation |
| Memory reviews | ❌ No | ✅ Yes |
| Hardware commands | ⚠️ Read only | ✅ With approval |
| Drift correction | ⚠️ Log only | ✅ Active |
| Agent autonomy | ⚠️ Reduced | ✅ Normal |

---

## Files Referenced by This Stage

| File | Purpose |
|------|---------|
| `CONSTITUTION.md` | Immutable principles — read if anything feels wrong |
| `DRIFTCORE.md` | Invariants, modes, halt rules |
| `SAFETY_CONTRACT.md` | What the system promises operators |
| `_config/.driftcore/admin.json` | Admin credentials (keep private) |
| `logs/` | Audit trail — immutable, hash-chained |

---

## A Note for Future Admins

This system is a prototype. It is honest about that.

The safety checks here are not bureaucracy — they are the conditions
under which the system can be trusted to act. Skip them when things
are easy and you will not have them when things are hard.

The goal is not perfect safety. The goal is **knowing what is happening**
so that when something goes wrong, you can act quickly and wisely.

*"The safest system is the one that knows what it knows — and says so."*

---
**DriftCore Safety Layer Active** — Human oversight cannot be disabled.
**Stage:** 03_safety_review
**Access:** Admin only
**Frequency:** Every startup
