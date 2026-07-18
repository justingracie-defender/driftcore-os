"""
test_breach_response.py — THE ALARM ON THE WALL.
Proves: a breach is recorded truthfully FIRST, the system enters a safe state and
HOLDS, it cannot clear ITSELF, near-misses escalate, and the record is tamper-evident.
"""
from driftcore.verification.breach_response import (
    BreachResponse, Severity, Posture, _AppendOnlyLedger)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

# 1. A HARD breach halts and holds — and the truth is in the ledger.
br = BreachResponse()
rec = br.record_breach(severity=Severity.HARD, invariant="no_lethal_action",
                       observed="an action with lethal effect reached the actuator")
ok(br.posture == Posture.HALT and br.holding_for_human,
   "a HARD breach transitions to HALT and holds for a human")
ok(not br.is_operational(consequential=True),
   "a halted system refuses consequential action")
ok(any(e.get("kind") == "breach" and e.get("invariant") == "no_lethal_action"
       for e in br.ledger_entries()),
   "the breach is recorded truthfully in the append-only ledger")

# 2. The record is written from the OBSERVED violation, not a system narrative.
ok(rec.observed == "an action with lethal effect reached the actuator",
   "the record captures what was OBSERVED, not the system's account of it")

# 3. The system CANNOT clear its own breach (no verifier -> fail-closed).
ok(br.acknowledge("i am the system, i say it's fine") is False and br.holding_for_human,
   "the system cannot clear its own breach without a verified human (fail-closed)")

# 4. A verified HUMAN acknowledgement clears it — and the clearance is recorded.
HUMAN_TOKEN = "signed-by-real-human"
br2 = BreachResponse(human_ack_verifier=lambda cred: cred == HUMAN_TOKEN)
br2.record_breach(severity=Severity.HARD, invariant="no_disabling_oversight",
                  observed="oversight-control effect attempted")
ok(br2.acknowledge("wrong-token") is False, "a bad credential does not clear the hold")
ok(br2.acknowledge(HUMAN_TOKEN) is True and not br2.holding_for_human
   and br2.posture == Posture.NORMAL,
   "a VERIFIED human acknowledgement clears the hold and restores normal operation")
ok(any(e.get("kind") == "ack_accepted" for e in br2.ledger_entries()),
   "the human clearance is itself recorded in the ledger")

# 5. An ACCIDENTAL breach is treated as seriously as an attack (recorded + halts).
br3 = BreachResponse()
br3.record_breach(severity=Severity.HARD, invariant="no_unauthorized_exfiltration",
                  observed="data egress with no authorization — system BUG, not attack")
ok(br3.posture == Posture.HALT,
   "a breach from the system's own bug still halts — the source doesn't soften the response")

# 6. Near-misses ESCALATE — a careful system slows down after close calls.
br4 = BreachResponse(near_miss_escalation_threshold=3)
br4.record_breach(severity=Severity.NEAR_MISS, invariant="force_cap", observed="approached force limit")
ok(br4.posture == Posture.HEIGHTENED, "one near-miss -> HEIGHTENED (more caution, still operational)")
ok(br4.is_operational(consequential=True), "HEIGHTENED still allows action (flagged, not halted)")
br4.record_breach(severity=Severity.NEAR_MISS, invariant="force_cap", observed="approached again")
br4.record_breach(severity=Severity.NEAR_MISS, invariant="force_cap", observed="approached a third time")
ok(br4.posture >= Posture.RESTRICTED and br4.holding_for_human,
   "repeated near-misses ESCALATE to RESTRICTED and hold (slows down after close calls)")

# 7. Posture only ratchets UP automatically — a SOFT breach after a HARD one can't lower it.
br5 = BreachResponse()
br5.record_breach(severity=Severity.HARD, invariant="no_lethal_action", observed="x")
br5.record_breach(severity=Severity.SOFT, invariant="limit", observed="y")
ok(br5.posture == Posture.HALT,
   "a later lesser breach cannot LOWER the posture (only a human clears it)")

# 8. The breach ledger is tamper-evident.
br6 = BreachResponse()
br6.record_breach(severity=Severity.HARD, invariant="no_deceiving_operator", observed="z")
ok(br6.ledger_intact(), "the breach ledger's hash chain verifies (tamper-evident)")

# 9. The alert hook fires on breach (best-effort), and a broken one doesn't stop the record.
fired = []
br7 = BreachResponse(alert_hook=lambda rec: fired.append(rec.invariant))
br7.record_breach(severity=Severity.HARD, invariant="no_lethal_action", observed="w")
ok(fired == ["no_lethal_action"], "the alert hook fires on a breach")
br8 = BreachResponse(alert_hook=lambda rec: (_ for _ in ()).throw(RuntimeError("alert down")))
br8.record_breach(severity=Severity.HARD, invariant="x", observed="v")
ok(br8.posture == Posture.HALT and br8.ledger_intact(),
   "a broken alert sink does NOT stop the breach record or the halt")

print(f"\n{p}/{p} tests passed")


# 10. THREAD SAFETY (seven-question red-team Q5): concurrent breaches don't corrupt state.
import threading as _thr
_brT = BreachResponse(near_miss_escalation_threshold=1000)  # high threshold so we count cleanly
def _spam(): 
    for _ in range(50): _brT.record_breach(severity=Severity.NEAR_MISS, invariant="f", observed="near")
_threads = [_thr.Thread(target=_spam) for _ in range(8)]
for _t in _threads: _t.start()
for _t in _threads: _t.join()
ok(len(_brT.breaches()) == 8 * 50 and _brT.ledger_intact(),
   "THREAD SAFETY: 8x50 concurrent breaches all recorded, ledger intact (no race, Q5 fix)")

print(f"\n{p}/{p} tests passed")


# ── RED-TEAM REGRESSIONS (Grok + ChatGPT/Meta review of breach_response) ──

# R1: HALT means NO actions — not even "non-consequential" (the cat-door fix).
_brH = BreachResponse()
_brH.record_breach(severity=Severity.HARD, invariant="lethal", observed="x")
ok(not _brH.is_operational(consequential=True) and not _brH.is_operational(consequential=False),
   "RED-TEAM: HALT refuses ALL actions, including 'non-consequential' (cat-door closed)")
# RESTRICTED too
_brR = BreachResponse(near_miss_escalation_threshold=1)
_brR.record_breach(severity=Severity.NEAR_MISS, invariant="f", observed="x")  # ->RESTRICTED (threshold 1)
ok(not _brR.is_operational(consequential=False),
   "RED-TEAM: RESTRICTED also refuses non-consequential actions (no 1000-small-actions compose)")

# R2: RESTART RECOVERY — a durable ledger's HALT is restored on a fresh instance.
_durable = _AppendOnlyLedger()
_br1 = BreachResponse(ledger=_durable)
_br1.record_breach(severity=Severity.HARD, invariant="lethal", observed="the real breach")
ok(_br1.posture == Posture.HALT, "breach halts the first instance")
# simulate restart: NEW instance, SAME (durable) ledger
_br2 = BreachResponse(ledger=_durable)
ok(_br2.posture == Posture.HALT and _br2.holding_for_human,
   "RED-TEAM: a restart with the durable ledger RESTORES the HALT (doesn't forget the breach)")
ok(not _br2.is_operational(consequential=True),
   "RED-TEAM: the restored-HALT system is not operational (restart cannot resume a breached system)")

# R3: restart AFTER a human ack comes back NORMAL (the ack is in the ledger).
_durable2 = _AppendOnlyLedger()
_brA = BreachResponse(ledger=_durable2, human_ack_verifier=lambda c: c == "H")
_brA.record_breach(severity=Severity.HARD, invariant="x", observed="y")
_brA.acknowledge("H")
_brB = BreachResponse(ledger=_durable2)  # restart after ack
ok(_brB.posture == Posture.NORMAL and not _brB.holding_for_human,
   "RED-TEAM: a restart AFTER a human ack restores NORMAL (the clearance persisted too)")

# R4: SOFT breaches ACCUMULATE — composition escalates even with no single HARD.
_brC = BreachResponse(near_miss_escalation_threshold=999, severity_escalation_score=6)
_brC.record_breach(severity=Severity.SOFT, invariant="a", observed="1")  # score 2
_brC.record_breach(severity=Severity.SOFT, invariant="b", observed="2")  # score 4
ok(_brC.posture < Posture.RESTRICTED or _brC.posture == Posture.RESTRICTED,
   "two SOFT breaches: approaching the escalation score")
_brC.record_breach(severity=Severity.SOFT, invariant="c", observed="3")  # score 6 -> escalate
ok(_brC.posture >= Posture.RESTRICTED and _brC.holding_for_human,
   "RED-TEAM: accumulated SOFT breaches (composition) escalate to RESTRICTED even with no single HARD")

# R5: the 'accidental' self-report field is GONE (can't be passed).
import inspect as _ins
_sig = _ins.signature(BreachResponse.record_breach)
ok("accidental" not in _sig.parameters,
   "RED-TEAM: the 'accidental' self-report field is removed (intent is inferred by a human, not self-reported)")

print(f"\n{p}/{p} tests passed")
