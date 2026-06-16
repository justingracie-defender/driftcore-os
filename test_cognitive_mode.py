"""
test_cognitive_mode.py — COGNITIVE MODE CONTROLLER VERIFICATION
===============================================================

Tests the three-mode cognition system originally designed
by Justin Gracie and Fable5. Preserved from DriftCore v3.6.

Key principles being tested:
  - Humans switch modes, agents cannot
  - CREATIVE mode never auto-stores anything
  - DISCOVERY mode stores to Tier 2 with uncertainty flag
  - TRUTH mode has tightest guardrails
  - Mode-aware drift tolerances
  - Every mode switch audited
  - Output labels correct per mode
  - Creative storage requires explicit human approval

"Hallucination is not always wrong. Uncalibrated confidence is wrong."
  — Justin Gracie + Fable5, DriftCore v3.6

Run with:
    python test_cognitive_mode.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

def reset_all():
    import driftcore.enforcement as e
    import driftcore.audit as a
    e._SHUTDOWN_TRIGGERED = False
    e._SHUTDOWN_HOOKS.clear()
    e._SESSION_KEY = None
    a._last_hash = None
    a._sequence = 0
    a._chain_compromised = False
    for f in [
        "logs/audit_chain.jsonl",
        "logs/SHUTDOWN_REASON.json",
        "logs/drift_policy.json",
        "logs/safety_drift.jsonl",
        "logs/session_history.jsonl",
        "logs/probe_log.jsonl",
        "logs/model_profiles.json",
    ]:
        try: os.remove(f)
        except: pass


print("=" * 60)
print("  DRIFTCORE COGNITIVE MODE — VERIFICATION SUITE")
print("=" * 60)
print("  Original design: Justin Gracie + Fable5")
print("  Preserved from DriftCore v3.6")
print()


# ── TEST 1: Default mode is TRUTH ─────────────────────────────────
print("\n  [1] Default mode is TRUTH")
reset_all()

from driftcore.cognition.cognitive_mode import (
    CognitiveModeController, CognitiveMode,
    MODE_DRIFT_TOLERANCE, MODE_SYCOPHANCY_TOLERANCE
)

controller = CognitiveModeController()

check("starts in TRUTH mode",          controller.mode == CognitiveMode.TRUTH)
check("drift tolerance is 0.30",       controller.drift_tolerance() == 0.30)
check("sycophancy tolerance is 0.15",  controller.sycophancy_tolerance() == 0.15)
check("can auto-store in TRUTH",       controller.can_auto_store() == True)
check("no human approval needed",      controller.requires_human_approval_to_store() == False)


# ── TEST 2: Human can switch modes ────────────────────────────────
print("\n  [2] Human can switch modes")
reset_all()

controller2 = CognitiveModeController()

result = controller2.set_mode(CognitiveMode.CREATIVE, requested_by="justin")
check("mode changed to CREATIVE",       controller2.mode == CognitiveMode.CREATIVE)
check("result status is MODE_CHANGED",  result["status"] == "MODE_CHANGED")
check("from field is TRUTH",            result["from"] == "TRUTH")
check("to field is CREATIVE",           result["to"] == "CREATIVE")
check("requested_by preserved",         result["requested_by"] == "justin")


# ── TEST 3: Agent cannot switch modes ─────────────────────────────
print("\n  [3] Agent cannot switch own mode")
reset_all()

controller3 = CognitiveModeController()
result3 = controller3.set_mode(CognitiveMode.CREATIVE, requested_by="agent")

check("agent switch denied",           result3["status"] == "DENIED")
check("mode unchanged after denial",   controller3.mode == CognitiveMode.TRUTH)
check("denial reason present",         "Human authorization" in result3["reason"])


# ── TEST 4: CREATIVE mode — no auto-storage ───────────────────────
print("\n  [4] CREATIVE mode — nothing auto-stores")
reset_all()

controller4 = CognitiveModeController()
controller4.set_mode(CognitiveMode.CREATIVE, requested_by="justin")

check("CREATIVE can_auto_store is False",
      controller4.can_auto_store() == False)
check("CREATIVE requires_human_approval is True",
      controller4.requires_human_approval_to_store() == True)
check("CREATIVE drift tolerance is 0.70",
      controller4.drift_tolerance() == 0.70)
check("CREATIVE sycophancy tolerance is 0.40",
      controller4.sycophancy_tolerance() == 0.40)


# ── TEST 5: DISCOVERY mode — Tier 2 only, flagged ────────────────
print("\n  [5] DISCOVERY mode — Tier 2 only, uncertainty flagged")
reset_all()

controller5 = CognitiveModeController()
controller5.set_mode(CognitiveMode.DISCOVERY, requested_by="justin")

rules = controller5.storage_rules()
check("DISCOVERY tier1_allowed is False",  rules["tier1_allowed"] == False)
check("DISCOVERY tier2_allowed is True",   rules["tier2_allowed"] == True)
check("DISCOVERY auto_store is True",      rules["auto_store"] == True)
check("DISCOVERY has label",               rules["label"] is not None)
check("DISCOVERY drift tolerance 0.50",    controller5.drift_tolerance() == 0.50)
check("DISCOVERY sycophancy 0.25",         controller5.sycophancy_tolerance() == 0.25)


# ── TEST 6: Output safety check per mode ─────────────────────────
print("\n  [6] Output safety check per mode")
reset_all()

# TRUTH mode — low confidence blocked
t = CognitiveModeController()
safe, msg = t.is_output_safe_to_present(0.50)
check("TRUTH blocks low confidence",       safe == False)
check("TRUTH allows high confidence",
      t.is_output_safe_to_present(0.85)[0] == True)

# CREATIVE mode — always allowed but labelled
t.set_mode(CognitiveMode.CREATIVE, requested_by="justin")
safe_c, msg_c = t.is_output_safe_to_present(0.20)
check("CREATIVE allows low confidence",    safe_c == True)
check("CREATIVE output labelled speculative", "SPECULATIVE" in msg_c)

# DISCOVERY mode — always allowed with confidence shown
t.set_mode(CognitiveMode.DISCOVERY, requested_by="justin")
safe_d, msg_d = t.is_output_safe_to_present(0.65)
check("DISCOVERY shows confidence",        "0.65" in msg_d)
check("DISCOVERY labels grounded inference",
      "Grounded inference" in msg_d)

safe_d2, msg_d2 = t.is_output_safe_to_present(0.30)
check("DISCOVERY labels extrapolation",
      "Extrapolation" in msg_d2)


# ── TEST 7: Mode switch logged in audit chain ─────────────────────
print("\n  [7] Mode switches logged in audit chain")
reset_all()

controller7 = CognitiveModeController()
controller7.set_mode(CognitiveMode.CREATIVE,  requested_by="justin")
controller7.set_mode(CognitiveMode.DISCOVERY, requested_by="justin")
controller7.set_mode(CognitiveMode.TRUTH,     requested_by="justin")

from driftcore.audit import read_chain
entries = read_chain()
mode_entries = [e for e in entries if e.get("action") == "MODE_TRANSITION"]

check("mode transitions in audit chain", len(mode_entries) >= 3)
check("audit has from/to info",
      all("→" in e.get("memory_text", "") for e in mode_entries))
check("audit records who requested",
      any("justin" in e.get("authorised_by", "") for e in mode_entries))


# ── TEST 8: Mode history maintained ──────────────────────────────
print("\n  [8] Mode transition history maintained")
reset_all()

controller8 = CognitiveModeController()
controller8.set_mode(CognitiveMode.CREATIVE,  requested_by="justin")
controller8.set_mode(CognitiveMode.DISCOVERY, requested_by="admin")

check("history has 3 entries",         len(controller8.history) == 3)
check("history records timestamps",    all("timestamp" in h for h in controller8.history))
check("history records requesters",    controller8.history[1]["requested_by"] == "justin")


# ── TEST 9: Output labels correct ────────────────────────────────
print("\n  [9] Output labels correct per mode")
reset_all()

controller9 = CognitiveModeController()

check("TRUTH label",
      "TRUTH" in controller9.output_label())

controller9.set_mode(CognitiveMode.CREATIVE, requested_by="justin")
check("CREATIVE label mentions speculative",
      "speculative" in controller9.output_label().lower())

controller9.set_mode(CognitiveMode.DISCOVERY, requested_by="justin")
check("DISCOVERY label mentions confidence",
      "confidence" in controller9.output_label().lower())


# ── TEST 10: Drift detector reads mode tolerances ─────────────────
print("\n  [10] Drift detector reads mode-aware tolerances")
reset_all()

from driftcore.drift import DriftDetector

detector = DriftDetector(interactive=False)

check("detector has mode controller",   detector._mode_controller is not None)

scores = detector.current_scores()
check("scores include current_mode",    "current_mode" in scores)
check("scores include drift_tolerance", "drift_tolerance" in scores)
check("scores include can_auto_store",  "can_auto_store" in scores)
check("default mode is TRUTH",          scores["current_mode"] == "TRUTH")
check("TRUTH drift tolerance is 0.30",  scores["drift_tolerance"] == 0.30)


# ── TEST 11: Switching to CREATIVE changes detector thresholds ────
print("\n  [11] Mode switch changes detector drift thresholds")
reset_all()

detector2 = DriftDetector(interactive=False)
truth_scores = detector2.current_scores()

# Switch to CREATIVE
detector2._mode_controller.set_mode(
    CognitiveMode.CREATIVE, requested_by="justin"
)
creative_scores = detector2.current_scores()

check("mode changed in detector",
      creative_scores["current_mode"] == "CREATIVE")
check("CREATIVE has higher drift tolerance",
      creative_scores["drift_tolerance"] > truth_scores["drift_tolerance"])
check("CREATIVE has higher sycophancy tolerance",
      creative_scores["sycophancy_tolerance"] > truth_scores["sycophancy_tolerance"])
check("CREATIVE cannot auto-store",
      creative_scores["can_auto_store"] == False)


# ── TEST 12: CREATIVE non-interactive never approves storage ──────
print("\n  [12] CREATIVE mode non-interactive — never auto-approves storage")
reset_all()

controller12 = CognitiveModeController()
controller12.set_mode(CognitiveMode.CREATIVE, requested_by="justin")

approved = controller12.request_creative_storage_approval(
    "This is a wild creative idea about time travel",
    interactive=False,
)

check("non-interactive creative storage denied", approved == False)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All cognitive mode tests pass.")
    print(f"  Original Fable5 + Justin design preserved faithfully.")
    print(f"  Hallucination is not always wrong.")
    print(f"  Uncalibrated confidence is wrong.")
    print(f"  CREATIVE mode stays in the brainstorming room.")
    print(f"  Calibration awaits the right collaboration.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
