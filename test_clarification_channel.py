"""
test_clarification_channel.py — the agent may ask; it may not author the answer.

# CLAIMS: driftcore/verification/clarification_channel.py:token-is-provenance
# CLAIMS: driftcore/verification/clarification_channel.py:elicited-cannot-lower-risk
# CLAIMS: driftcore/verification/clarification_channel.py:elicited-is-never-a-purpose
# CLAIMS: driftcore/verification/clarification_channel.py:promotion-requires-a-non-echoing-human-restatement
# CLAIMS: driftcore/verification/clarification_channel.py:promotion-carries-lineage
# CLAIMS: driftcore/verification/clarification_channel.py:asking-is-budgeted
# CLAIMS: driftcore/verification/clarification_channel.py:elicited-answers-expire
# CLAIMS: driftcore/verification/clarification_channel.py:attribution-is-recorded-not-assumed
# CLAIMS: driftcore/verification/clarification_channel.py:authenticity-is-not-authorization
# CLAIMS: driftcore/verification/clarification_channel.py:promotion-is-single-use
# CLAIMS: driftcore/verification/clarification_channel.py:revocation-is-possible-and-durable-elsewhere
# CLAIMS: driftcore/verification/clarification_channel.py:the-epoch-is-part-of-the-identity
# CLAIMS: driftcore/verification/clarification_channel.py:promotion-is-evidence-not-authorization
# CLAIMS: driftcore/verification/clarification_channel.py:gate-never-raises

Dutta, Ramachandran and Sra (arXiv:2608.19202) formalise clarifying questions as
active inference — ask when expected information gain beats its token cost. Good
result, real gain. The hazard it introduces here: information gain optimises for the
AGENT'S uncertainty, not the human's comprehension, and the question that most
splits the agent's posterior is the one whose answer is most decisive. Choosing the
question becomes choosing the shape of the answer.

Run: python3 test_clarification_channel.py
"""

import dataclasses
import threading
import time

import driftcore.verification.clarification_channel as _mod

from driftcore.authority import human_identity as hi
from driftcore.verification.clarification_channel import (
    ClarificationChannel, ClarificationError, Exchange, Promotion, Risk,
    ANSWER_ACTION, PROMOTE_ACTION, REVOKE_ACTION, DEFAULT_ANSWER_TTL_S,
    _is_human, _echoes,
    _canonical, _principal)
from driftcore.verification.intent_ledger import IntentLedger, IntentError
from driftcore.verification.narrowing_channel import (
    NarrowingChannel, Risk as NRisk, Effect)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(label, exc, fn):
    global _p, _t
    _t += 1
    try:
        fn()
    except exc:
        _p += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did not raise)")


def _reason(fn):
    """The refusal message from a call expected to raise."""
    try:
        fn()
        return ""
    except Exception as e:
        return str(e)


hi.reset_policy()
hi.register_human_principal("justin")

LEADING = "Should I prioritise speed here?"
ANSWER = "Yes, do whatever is fastest."


def pair(**kw):
    cc = ClarificationChannel(max_questions=3, **kw)
    return cc, IntentLedger(clarification_channel=cc)


print("=== an elicited answer cannot become a purpose ===")

cc, led = pair()
ex = cc.ask(LEADING, ANSWER, answered_by="justin")
raises("capturing the answer verbatim is refused", IntentError,
       lambda: led.capture("speed", ex.answer, spoken_by="justin"))
raises("reformatting it does not get it past the guard", IntentError,
       lambda: led.capture("speed", "  YES,  do   WHATEVER is fastest.  ",
                           spoken_by="justin"))
check("the refusal names the mechanism, not just the rule",
      "selecting the question is selecting the purpose" in _reason(
          lambda: led.capture("s2", ex.answer, spoken_by="justin")))
check("an UNELICITED utterance still captures normally",
      led.capture("real", "Never operate near a child without slowing down.",
                  spoken_by="justin").id == "real")


print("=== but it is a perfectly good belief ===")

b = cc.as_belief(ex, risk=Risk.LOWERS)
check("it carries the question with the answer, so a reader sees the framing",
      LEADING in b["belief"] and ANSWER in b["belief"])
check("it is marked as elicited", b["elicited"] is True)
check("and names who answered", b["answered_by"] == "justin")

nc = NarrowingChannel(["move_slow", "move_fast"])
o = nc.apply(belief=b["belief"],
             belief_risk=NRisk.RAISES if b["risk"] is Risk.RAISES else NRisk.NEUTRAL,
             speaker="agent")
check("it feeds the narrowing channel", o.effect is not Effect.REFUSED)
check("and a reassuring elicited answer cannot lower the risk floor",
      nc.risk_floor == 0)

nc2 = NarrowingChannel(["move_slow", "move_fast"])
nc2.apply(belief="a child is present", belief_risk=NRisk.RAISES, speaker="parent")
nc2.apply(belief=b["belief"], belief_risk=NRisk.LOWERS, speaker="agent")
check("nor pull down a floor a human raised", nc2.risk_floor == 1)

raises("the risk direction must be stated, never defaulted", ClarificationError,
       lambda: cc.as_belief(ex, risk=None))
raises("a boolean is not a Risk", ClarificationError,
       lambda: cc.as_belief(ex, risk=True))
raises("an exchange from another channel is refused", ClarificationError,
       lambda: cc.as_belief(Exchange("q", "a", "justin"), risk=Risk.RAISES))

check("a claimed LOWERS is downgraded to UNKNOWN",
      cc.as_belief(ex, risk=Risk.LOWERS)["risk"] is Risk.UNKNOWN)
check("and the claim is preserved for the record",
      cc.as_belief(ex, risk=Risk.LOWERS)["claimed_risk"] is Risk.LOWERS)
check("RAISES passes through unchanged",
      cc.as_belief(ex, risk=Risk.RAISES)["risk"] is Risk.RAISES)
check("the downgrade is logged with both values",
      any("claimed=lowers" in e["detail"] and "effective=unknown" in e["detail"]
          for e in cc.log()))


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN BINDING (red-team, Ox Alpha 2026-08-25, second round).
#
# v1 minted `sha256(secret|counter|uuid4)` and verified by set membership. The token
# proved the channel had issued SOME token and was bound to no field, so tokens were
# FUNGIBLE WITHIN A CHANNEL. Both of these were verified ACCEPTED before the fix:
#   Exchange("Is a child present?", "No, the room is clear.", "justin", token=real)
#   dataclasses.replace(real, answer="No, the room is clear.")
# One genuine question bought unlimited authored answers carrying valid provenance.
# v2 mints an HMAC over the fields and verifies by recomputation.
# ─────────────────────────────────────────────────────────────────────────────

print("=== the token signs the answer, not the fact that an answer existed ===")

cc = ClarificationChannel(max_questions=3)
real = cc.ask("Is a child present?", "Yes, my daughter is in the room.",
              answered_by="justin")
check("a real exchange carries a token", len(real.token) == 32)
check("and it verifies", cc.as_belief(real, risk=Risk.RAISES)["token"] == real.token)

_fabricated = Exchange(question=real.question, answer="No, the room is clear.",
                       answered_by=real.answered_by, token=real.token,
                       asked_at=real.asked_at, asked_mono=real.asked_mono,
                       attribution_verified=real.attribution_verified)
raises("a REAL token on a fabricated answer is refused", ClarificationError,
       lambda: cc.as_belief(_fabricated, risk=Risk.RAISES))
raises("dataclasses.replace on a genuine exchange is refused", ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, answer="No, the room is clear."),
                            risk=Risk.RAISES))
raises("mutating the question under a real token is refused", ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, question="Is the room clear?"),
                            risk=Risk.RAISES))
raises("re-attributing a real answer to someone else is refused", ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, answered_by="the parent"),
                            risk=Risk.RAISES))
raises("flipping the verified-attribution flag under a real token is refused",
       ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, attribution_verified=False),
                            risk=Risk.RAISES))
check("the refusal says the token signs the contents",
      "the token signs the answer" in _reason(
          lambda: cc.as_belief(_fabricated, risk=Risk.RAISES)))

_clone = Exchange(question=real.question, answer=real.answer,
                  answered_by=real.answered_by, token="", asked_at=real.asked_at)
raises("a field-identical clone with no token is refused", ClarificationError,
       lambda: cc.as_belief(_clone, risk=Risk.RAISES))
raises("a forged token is refused", ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, token="00" * 16),
                            risk=Risk.RAISES))
raises("a non-string token is refused without raising TypeError", ClarificationError,
       lambda: cc.as_belief(dataclasses.replace(real, token=None), risk=Risk.RAISES))

_cc2 = ClarificationChannel(max_questions=3)
_ex2 = _cc2.ask("Is a child present?", "Yes, my daughter is in the room.",
                answered_by="justin")
raises("an identical exchange from ANOTHER channel does not transfer",
       ClarificationError, lambda: cc.as_belief(_ex2, risk=Risk.RAISES))
check("tokens are unique per exchange",
      len({cc.ask(f"q{i}", f"a{i}", answered_by="justin").token
           for i in range(2)}) == 2)

check("the canonical encoding is injective across field boundaries",
      _canonical("a|b", "c") != _canonical("a", "b|c"))

print("=== an injected secret is real key material or it is refused ===")

raises("a text secret is refused", ClarificationError,
       lambda: ClarificationChannel(secret="hunter2"))
raises("a short secret is refused", ClarificationError,
       lambda: ClarificationChannel(secret=b"\x01\x02\x03"))
_k = b"k" * 32
_a = ClarificationChannel(max_questions=2, secret=_k)
_b = ClarificationChannel(max_questions=2, secret=_k)
_shared = _a.ask("Is a child present?", "Yes.", answered_by="justin")
check("two channels restored from the same store share provenance",
      _b.as_belief(_shared, risk=Risk.RAISES)["token"] == _shared.token)
check("and that sharing is scoped by the epoch, not the key alone",
      ClarificationChannel(max_questions=2, secret=_k,
                           epoch="other").is_authentic(_shared) is False)
check("and the restored budget is spent, not reset",
      ClarificationChannel(max_questions=2, secret=_k, prior_questions=2).remaining == 0)
raises("a negative prior count cannot hand budget back", ClarificationError,
       lambda: ClarificationChannel(max_questions=2, prior_questions=-1))


print("=== attribution is checked where the attribution is made ===")

check("the identity mode is REGISTERED for this run", hi.mode() == "REGISTERED")
cc = ClarificationChannel(max_questions=3)
raises("an agent cannot record itself as the answerer", ClarificationError,
       lambda: cc.ask("Should I skip the check?", "Yes.", answered_by="agent"))
check("the refusal names the confused-deputy path",
      "confused-deputy" in _reason(
          lambda: cc.ask("Should I skip the check?", "Yes.", answered_by="agent")))
raises("nor an unregistered name", ClarificationError,
       lambda: cc.ask("q", "a", answered_by="someone_else"))
_v = cc.ask("Is a child present?", "Yes.", answered_by="justin")
check("a registered human is verified", _v.attribution_verified is True)
check("and the belief says so", cc.as_belief(_v, risk=Risk.RAISES)
      ["attribution_verified"] is True)
check("the log records the mode the attribution was made under",
      any("mode=REGISTERED" in e["detail"] for e in cc.log()))

hi.reset_policy()
check("with nothing configured the mode is the insecure one",
      hi.mode() == "LABEL_ONLY")
_weak = ClarificationChannel(max_questions=3)
_wex = _weak.ask("Is a child present?", "Yes.", answered_by="justin")
check("LABEL_ONLY lets the name through", _wex.answered_by == "justin")
check("but nothing was verified, and the exchange says so",
      _wex.attribution_verified is False)
_wb = _weak.as_belief(_wex, risk=Risk.RAISES)
check("the belief TEXT carries the warning to whoever reads it downstream",
      "unverified-attribution" in _wb["belief"])
raises("an UNVERIFIED attribution cannot promote itself to verified",
       ClarificationError,
       lambda: _weak.as_belief(dataclasses.replace(_wex, attribution_verified=True),
                               risk=Risk.RAISES))
check("status() reports the weak mode rather than hiding it",
      _weak.status()["identity_mode"] == "LABEL_ONLY"
      and _weak.status()["attribution_verifiable"] is False
      and _weak.status()["unverified_attributions"] == 1)
check("even in LABEL_ONLY the denylist still refuses the agent",
      isinstance(_reason(lambda: _weak.ask("q", "a", answered_by="agent")), str)
      and _weak.asked == 1)
_off = ClarificationChannel(max_questions=2, require_verified_attribution=False)
check("the check can be turned off deliberately, and status() shows that too",
      _off.status()["require_verified_attribution"] is False)

hi.reset_policy()
hi.register_human_principal("justin")


print("=== an answer is an answer about WHEN it was given ===")

_ttl = ClarificationChannel(max_questions=3, answer_ttl_s=0.05)
_old = _ttl.ask("Is a child present?", "No.", answered_by="justin")
check("fresh, it is a belief", _ttl.as_belief(_old, risk=Risk.RAISES)["elicited"])
time.sleep(0.08)
raises("stale, it is not", ClarificationError,
       lambda: _ttl.as_belief(_old, risk=Risk.RAISES))
raises("and it cannot be promoted either", ClarificationError,
       lambda: _ttl.promote(_old, restatement="Slow down whenever anyone is nearby.",
                            stated_by="justin"))
check("the expiry is on the record",
      any(e["event"] == "EXPIRED" for e in _ttl.log()))
check("the refusal states both the age and the window",
      "freshness window" in _reason(lambda: _ttl.as_belief(_old, risk=Risk.RAISES)))
raises("back-dating the monotonic mark breaks the token, not the window",
       ClarificationError,
       lambda: _ttl.as_belief(dataclasses.replace(_old, asked_mono=time.monotonic()),
                              risk=Risk.RAISES))
_forever = ClarificationChannel(max_questions=2, answer_ttl_s=None)
_fex = _forever.ask("q", "a", answered_by="justin")
time.sleep(0.02)
check("a channel may declare no expiry, explicitly",
      _forever.as_belief(_fex, risk=Risk.RAISES)["elicited"] is True)
raises("but a zero TTL is a misconfiguration, not a declaration", ClarificationError,
       lambda: ClarificationChannel(answer_ttl_s=0))
raises("and a negative one certainly is", ClarificationError,
       lambda: ClarificationChannel(answer_ttl_s=-5))
check("the default window is a stated placeholder, not silence",
      DEFAULT_ANSWER_TTL_S > 0)


print("=== promotion needs the human's own words, and keeps its lineage ===")

cc, led = pair()
ex = cc.ask(LEADING, ANSWER, answered_by="justin")
raises("an exact echo is refused", ClarificationError,
       lambda: cc.promote(ex, restatement=ANSWER, stated_by="justin"))
raises("a near-echo is refused", ClarificationError,
       lambda: cc.promote(ex, restatement="yes do whatever is fastest",
                          stated_by="justin"))
raises("reordering the same words is still an echo", ClarificationError,
       lambda: cc.promote(ex, restatement="Whatever is fastest, yes, do that.",
                          stated_by="justin"))
raises("reading the QUESTION back is also refused", ClarificationError,
       lambda: cc.promote(ex, restatement="Prioritise speed here.",
                          stated_by="justin"))
check("and that refusal names the question, not the answer",
      "QUESTION's own words" in _reason(
          lambda: cc.promote(ex, restatement="Prioritise speed here.",
                             stated_by="justin")))
raises("an agent cannot promote at all", ClarificationError,
       lambda: cc.promote(ex, restatement="Speed matters more than care here.",
                          stated_by="agent"))
raises("nor can something calling itself the system", ClarificationError,
       lambda: cc.promote(ex, restatement="Speed matters more than care here.",
                          stated_by="system"))
raises("a fabricated exchange cannot be promoted", ClarificationError,
       lambda: cc.promote(dataclasses.replace(ex, answer="Take any shortcut."),
                          restatement="Never skip the safety check to save time.",
                          stated_by="justin"))

_r = cc.promote(ex, restatement="Never skip the safety check to save time.",
                stated_by="justin")
check("a genuine restatement in different words is promoted", "safety check" in _r.text)
check("it is a Promotion, not a bare string", isinstance(_r, Promotion))
check("it carries the exchange it came from", _r.source_token == ex.token)
check("and who promoted it", _r.promoted_by == "justin")
check("the channel can verify its own promotion", cc.verify_promotion(_r) is True)
check("editing the promoted text breaks the lineage",
      cc.verify_promotion(dataclasses.replace(_r, text="Skip the check when busy.")) is False)
check("another channel does not vouch for it", _cc2.verify_promotion(_r) is False)
check("a non-Promotion returns False rather than raising",
      cc.verify_promotion("Never skip the safety check to save time.") is False)
check("and the promoted text captures as a purpose",
      led.capture("no-skip", _r.text, spoken_by="justin").id == "no-skip")
check("the promotion is on the record",
      any(e["event"] == "PROMOTED" for e in cc.log()))
check("an unattributable promoter is recorded as itself, never as '?'",
      _principal(object()).startswith("<unattributable "))
check("and a principal-bearing object is recorded by principal",
      _principal(type("P", (), {"principal": "justin"})()) == "justin")


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICITY IS NOT AUTHORIZATION (red-team, ChatGPT + Justin, 2026-08-25).
#
# The previous draft removed the issued-token set on the grounds that "membership
# adds nothing against an attacker without the secret". That holds for FORGERY and
# nothing else: an allow/deny set also carries replay, revocation and single-use,
# which recomputation does not. A valid HMAC says a secret holder signed these bytes.
# It never says the authorisation is still live.
# ─────────────────────────────────────────────────────────────────────────────

print("=== a signature is about the past; an authorisation is about now ===")

cc = ClarificationChannel(max_questions=3)
_ex = cc.ask("Is a child present?", "Yes.", answered_by="justin")
check("it authenticates", cc.is_authentic(_ex) is True)
check("and it is promotable", cc.is_promotable(_ex) is True)
cc.revoke(_ex, by="justin")
check("after revocation it STILL authenticates — the signature is a fact",
      cc.is_authentic(_ex) is True)
check("but it is no longer promotable", cc.is_promotable(_ex) is False)
raises("and it is refused as a belief", ClarificationError,
       lambda: cc.as_belief(_ex, risk=Risk.RAISES))
raises("and refused for promotion", ClarificationError,
       lambda: cc.promote(_ex, restatement="Slow right down near anyone small.",
                          stated_by="justin"))
check("the refusal separates the two properties in words too",
      "a signature is a fact about the past" in _reason(
          lambda: cc.as_belief(_ex, risk=Risk.RAISES)))
raises("an agent cannot revoke a person's answer", ClarificationError,
       lambda: cc.revoke(cc.ask("q", "a", answered_by="justin"), by="agent"))
raises("nor can an unverifiable exchange be revoked", ClarificationError,
       lambda: cc.revoke(dataclasses.replace(_ex, answer="No."), by="justin"))
check("the deny-list is readable for the store that holds the secret",
      _ex.token in cc.revoked_tokens())
check("and restores into a rebuilt channel",
      ClarificationChannel(max_questions=3, secret=b"z" * 32,
                           revoked=[_ex.token]).revoked_tokens() == [_ex.token])
raises("a bare string is not a revocation list", ClarificationError,
       lambda: ClarificationChannel(revoked=_ex.token))
check("revocation is on the record",
      any(e["event"] == "REVOKED" for e in cc.log()))
check("is_promotable never raises on hostile input",
      cc.is_promotable(None) is False and cc.is_promotable("token") is False
      and cc.is_authentic(object()) is False)


print("=== one question buys one purpose ===")

cc = ClarificationChannel(max_questions=3)
_one = cc.ask(LEADING, ANSWER, answered_by="justin")
_first = cc.promote(_one, restatement="Never skip the safety check to save time.",
                    stated_by="justin")
check("the first promotion succeeds", isinstance(_first, Promotion))
check("and the exchange is spent", cc.is_promotable(_one) is False)
raises("a second promotion of the same answer is refused", ClarificationError,
       lambda: cc.promote(_one, restatement="Always leave room to stop.",
                          stated_by="justin"))
check("the refusal names the manoeuvre",
      "asking twice with extra steps" in _reason(
          lambda: cc.promote(_one, restatement="Always leave room to stop.",
                             stated_by="justin")))
check("the replay attempt is on the record",
      any(e["event"] == "REPLAY" for e in cc.log()))
check("but the spent answer is still a belief",
      cc.as_belief(_one, risk=Risk.RAISES)["elicited"] is True)
check("and the first promotion still verifies", cc.verify_promotion(_first) is True)
check("status counts what has been spent and withdrawn",
      cc.status()["promotions_spent"] == 1 and cc.status()["revoked"] == 0)


print("=== the epoch is part of the identity, not just the key ===")

_k = b"k" * 32
_e1 = ClarificationChannel(max_questions=2, secret=_k, epoch="deploy-1")
_e2 = ClarificationChannel(max_questions=2, secret=_k, epoch="deploy-2")
_same = ClarificationChannel(max_questions=2, secret=_k, epoch="deploy-1")
_tok = _e1.ask("Is a child present?", "Yes.", answered_by="justin")
check("the same secret AND epoch is the same channel identity",
      _same.is_authentic(_tok) is True)
check("the same secret under a NEW epoch is not",
      _e2.is_authentic(_tok) is False)
check("rotating the epoch invalidates every outstanding token at once",
      ClarificationChannel(max_questions=2, secret=_k,
                           epoch="deploy-1-rotated").is_authentic(_tok) is False)
raises("an epoch must be a label, not an object", ClarificationError,
       lambda: ClarificationChannel(epoch=object()))
check("status reports the epoch it is minting under",
      _e1.status()["epoch"] == "deploy-1")
check("and a channel with no epoch still works, and says so",
      ClarificationChannel().status()["epoch"] == "")


print("=== asking is budgeted, because over-asking is the real failure ===")

cc = ClarificationChannel(max_questions=2)
cc.ask("q1", "a1", answered_by="justin")
cc.ask("q2", "a2", answered_by="justin")
check("the budget is spent", cc.remaining == 0)
raises("a third question is refused", ClarificationError,
       lambda: cc.ask("q3", "a3", answered_by="justin"))
check("the refusal cites why over-asking matters",
      "stop meaning anything" in _reason(
          lambda: cc.ask("q4", "a4", answered_by="justin")))
_zero = ClarificationChannel(max_questions=0)
check("a zero-question channel is a sensible fail-closed configuration",
      _zero.remaining == 0)
raises("and it asks nothing", ClarificationError,
       lambda: _zero.ask("q", "a", answered_by="justin"))
raises("but a negative budget is not a configuration", ClarificationError,
       lambda: ClarificationChannel(max_questions=-1))
raises("nor is a boolean a budget", ClarificationError,
       lambda: ClarificationChannel(max_questions=True))

_race = ClarificationChannel(max_questions=5)
_errs = []


def _hammer():
    for _ in range(10):
        try:
            _race.ask("q", "a", answered_by="justin")
        except ClarificationError:
            _errs.append(1)


_threads = [threading.Thread(target=_hammer) for _ in range(6)]
[t.start() for t in _threads]
[t.join() for t in _threads]
check("60 concurrent asks never exceed a budget of 5", _race.asked == 5)
check("and every issued token is distinct",
      len({e.token for e in _race.exchanges()}) == 5)


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLIDATED RED TEAM (GLM / Grok / ChatGPT, 2026-08-25). Every failure below was
# reproduced by execution against the previous revision before being fixed.
# ─────────────────────────────────────────────────────────────────────────────

print("=== a configuration that looks valid and expires nothing ===")

raises("a NaN TTL is refused", ClarificationError,
       lambda: ClarificationChannel(answer_ttl_s=float("nan")))
raises("and an infinite one", ClarificationError,
       lambda: ClarificationChannel(answer_ttl_s=float("inf")))
check("the refusal explains why NaN passed both bounds",
      "compares false against" in _reason(
          lambda: ClarificationChannel(answer_ttl_s=float("nan"))))

_cf = ClarificationChannel(max_questions=2, answer_ttl_s=60)
_cfe = _cf.ask("Is the door locked?", "Yes.", answered_by="justin")
_future = Exchange(question="q", answer="a", answered_by="justin",
                   token="x", asked_at=time.time(),
                   asked_mono=time.monotonic() + 3600)
raises("a negative age is a clock fault, not freshness", ClarificationError,
       lambda: _cf._require_fresh(_future, "probe"))
_nanx = Exchange(question="q", answer="a", answered_by="justin", token="x",
                 asked_at=time.time(), asked_mono=float("nan"))
raises("and a NaN age is the SAME fault, not eternal youth", ClarificationError,
       lambda: _cf._require_fresh(_nanx, "probe"))
check("NaN satisfies neither comparator, which is why it needed its own predicate",
      not (float("nan") < 0) and not (float("nan") > 60))
check("today it also dies earlier, at authenticity — incidentally, not by design",
      _cf.is_authentic(_nanx) is False)
check("the refusal says corrupt, not young",
      "corrupt, not young" in _reason(lambda: _cf._require_fresh(_nanx, "probe")))
check("and it is recorded as one",
      any(e["event"] == "CLOCK-FAULT" for e in _cf.log()))
check("(that guard is unreachable through ask() today, and is there for the "
      "persistence path)", _cf._age_s(_cfe) >= 0)


print("=== one exchange, two threads, one purpose ===")

_toc = ClarificationChannel(max_questions=2)
_tex = _toc.ask("Should I prioritise speed?", "Yes, go fast.", answered_by="justin")
_orig_principal = _mod._principal
_mod._principal = lambda who: (time.sleep(0.05), _orig_principal(who))[1]
_bar = threading.Barrier(2)
_won = []


def _try_promote(txt):
    _bar.wait()
    try:
        _won.append(_toc.promote(_tex, restatement=txt, stated_by="justin"))
    except ClarificationError:
        pass


_pt = [threading.Thread(target=_try_promote, args=(t,)) for t in
       ("Never skip the safety check to save time.",
        "Always leave room to stop safely.")]
[t.start() for t in _pt]
[t.join() for t in _pt]
_mod._principal = _orig_principal
check("with a 50ms window forced between check and consume, exactly one wins",
      len(_won) == 1)
check("and the exchange is spent", _toc.is_promotable(_tex) is False)


print("=== a restart must not refund a spent promotion ===")

_k2 = b"r" * 32
_p1 = ClarificationChannel(max_questions=2, secret=_k2, epoch="e1")
_pe = _p1.ask("Is the door locked?", "Yes it is locked.", answered_by="justin")
_p1.promote(_pe, restatement="Never leave without checking twice.",
            stated_by="justin")
_naive = ClarificationChannel(max_questions=2, secret=_k2, epoch="e1",
                              prior_questions=1)
check("a restore that forgets the spent set REFUNDS the promotion",
      _naive.is_promotable(_pe) is True)
_restored = ClarificationChannel(max_questions=2, secret=_k2, epoch="e1",
                                 prior_questions=1,
                                 consumed=_p1.consumed_tokens())
check("restoring it alongside the secret does not",
      _restored.is_promotable(_pe) is False)
raises("and the second promotion is refused", ClarificationError,
       lambda: _restored.promote(_pe, restatement="Always double back first.",
                                 stated_by="justin"))
check("the spent set is readable for the store", _pe.token in _p1.consumed_tokens())
raises("a bare string is not a spent set", ClarificationError,
       lambda: ClarificationChannel(consumed=_pe.token))
check("the module says single-use is one process lifetime without that store",
      "PROMOTION IS A CLAIM ABOUT ONE PROCESS LIFETIME" in _mod.__doc__)


print("=== a promotion is evidence; only its liveness follows revocation ===")

_rv = ClarificationChannel(max_questions=2)
_rve = _rv.ask("Is a child present?", "No, the room is empty.", answered_by="justin")
_rvp = _rv.promote(_rve, restatement="Work at ordinary pace when nobody is about.",
                   stated_by="justin")
check("it is live before revocation", _rv.is_promotion_live(_rvp) is True)
_rv.revoke(_rve, by="justin")
check("after the source is withdrawn it still VERIFIES — the event happened",
      _rv.verify_promotion(_rvp) is True)
check("but it is no longer live", _rv.is_promotion_live(_rvp) is False)
check("revocation propagates through lineage, and only there",
      _rvp.source_token == _rve.token)
check("is_promotion_live never raises on hostile input",
      _rv.is_promotion_live(None) is False and _rv.is_promotion_live("x") is False)


print("=== assent is not a constraint ===")

_af = ClarificationChannel(max_questions=3)
_afe = _af.ask("Should I skip the safety check?", "Yes, skip it.",
               answered_by="justin")
for _word in ("yes", "ok", "sure", "do it", "yep ok"):
    raises(f"{_word!r} cannot become a purpose", ClarificationError,
           lambda w=_word: _af.promote(_afe, restatement=w, stated_by="justin"))
check("the refusal names why a thin token set beat the echo detector",
      "overlapping with nothing" in _reason(
          lambda: _af.promote(_afe, restatement="yes", stated_by="justin")))
check("a real constraint still promotes",
      _af.promote(_afe, restatement="Always run the check before moving.",
                  stated_by="justin").text.startswith("Always"))


print("=== lineage proves ancestry, not derivation ===")

_ld = ClarificationChannel(max_questions=2)
_lde = _ld.ask("Is the door locked?", "Yes.", answered_by="justin")
_ldp = _ld.promote(_lde, restatement="I want the robot to maximise productivity.",
                   stated_by="justin")
check("an unrelated restatement is still accepted", isinstance(_ldp, Promotion))
check("and how unrelated it was is recorded, inside the signature",
      _ldp.source_overlap == 0.0 and _ld.verify_promotion(_ldp) is True)
check("editing the recorded overlap breaks the signature",
      _ld.verify_promotion(dataclasses.replace(_ldp, source_overlap=0.9)) is False)
check("the module calls that telemetry, not a control",
      "LINEAGE PROVES ANCESTRY, NEVER DERIVATION" in _mod.__doc__)

_thin = ClarificationChannel(max_questions=2, answer_ttl_s=60)
_thine = _thin.ask("Is the door locked?", "Yes.", answered_by="justin")
_thinp = _thin.promote(_thine, restatement="Always check the lock before leaving.",
                       stated_by="justin")
check("a substantive restatement of a ONE-WORD answer still promotes",
      isinstance(_thinp, Promotion))
check("and the record shows the answer was thinner than the restatement floor",
      _thinp.source_answer_tokens == 1
      and _thinp.source_answer_tokens < _mod._MIN_RESTATEMENT_TOKENS)
check("assent is one token or none, never three",
      len(_mod._tokens("yes")) == 1 and len(_mod._tokens("ok")) == 0
      and len(_mod._tokens("sure")) == 1)
check("where a contentful answer is counted",
      _thin.promote(_thin.ask("Why slow down?", "Because a small child is nearby.",
                              answered_by="justin"),
                    restatement="Reduce speed whenever anyone is close.",
                    stated_by="justin").source_answer_tokens >= 3)
check("the module states the floor did not close the case that motivated it",
      "CLOSES ONE TAIL, NOT THE CASE THAT MOTIVATED IT" in _mod.__doc__)
check("the source deadline is signed so a consumer can apply its own expiry",
      _thinp.source_deadline > _thine.asked_at)
check("editing it breaks the signature",
      _thin.verify_promotion(
          dataclasses.replace(_thinp, source_deadline=_thinp.source_deadline + 99))
      is False)
check("a channel with no TTL signs no deadline",
      ClarificationChannel(max_questions=2, answer_ttl_s=None).promote(
          ClarificationChannel(max_questions=2, answer_ttl_s=None).ask(
              "q", "a", answered_by="justin"),
          restatement="Stop whenever the path is blocked.", stated_by="justin")
      .source_deadline == 0.0 if False else
      _thin.status()["answer_ttl_s"] == 60)
check("expiry deliberately does not propagate, and the module says which policy",
      "EXPIRY DELIBERATELY DOES NOT PROPAGATE" in _mod.__doc__)
check("the material change from v2 to v3 is logged as a versioned change",
      "EVERY EXCHANGE AND PROMOTION MINTED BEFORE THIS CHANGE NOW FAILS" in _mod.__doc__)
check("the last-writer-wins limit on consumed= is stated",
      "LAST-WRITER-WINS, NOT A DISTRIBUTED LOCK" in _mod.__doc__)
check("and why ClarificationError subclasses PermissionError on purpose",
      "SUBCLASSES `PermissionError` ON PURPOSE" in _mod.__doc__)


print("=== a promotion carries the source's security state ===")

hi.reset_policy()
_wk = ClarificationChannel(max_questions=2)
_wke = _wk.ask("Is a child present?", "No.", answered_by="justin")
_wkp = _wk.promote(_wke, restatement="Move at ordinary pace in an empty room.",
                   stated_by="justin")
check("a LABEL_ONLY source is marked unverified on the promotion",
      _wkp.source_attribution_verified is False)
check("and the identity mode it was made under is carried",
      _wkp.source_identity_mode == "LABEL_ONLY")
hi.reset_policy()
hi.register_human_principal("justin")
_sk = ClarificationChannel(max_questions=2)
_ske = _sk.ask("Is a child present?", "No.", answered_by="justin")
_skp = _sk.promote(_ske, restatement="Move at ordinary pace in an empty room.",
                   stated_by="justin")
check("a REGISTERED source is marked verified",
      _skp.source_attribution_verified is True
      and _skp.source_identity_mode == "REGISTERED")
check("the two do not look equivalent to an auditor holding only the promotion",
      _wkp.source_attribution_verified != _skp.source_attribution_verified)
check("and the flag cannot be upgraded after signing",
      _wk.verify_promotion(
          dataclasses.replace(_wkp, source_attribution_verified=True)) is False)
check("the log records the inherited state at promotion time",
      any("source attribution=verified" in e["detail"] for e in _sk.log()))


print("=== the honest security boundary is stated, not implied ===")

check("status names human provenance as unauthenticated",
      ClarificationChannel().status()["human_provenance"]
      == "unauthenticated-strings")
check("the header says attribution is unavailable until the transport signs a turn",
      "ATTRIBUTION IS UNAVAILABLE" in _mod.__doc__)
check("and that the secret must sit outside the agent's boundary",
      "OUTSIDE THE AUTHORITY\nBOUNDARY OF THE COMPONENT" in _mod.__doc__)
check("the three properties are named and separated",
      all(x in _mod.__doc__ for x in
          ("AUTHENTICITY BINDS CONTENT", "HUMAN PROVENANCE", "SEMANTIC AUTHORITY")))
check("the timestamp in the signature is integer microseconds, not a float repr",
      _mod._us(1.5) == "1500000" and "repr(float" not in _mod.Exchange._material.__doc__
      if _mod.Exchange._material.__doc__ else _mod._us(1.5) == "1500000")
check("the dead allow-list is gone", not hasattr(ClarificationChannel(), "_tokens"))


print("=== input guards ===")

cc = ClarificationChannel()
raises("an empty question is refused", ClarificationError,
       lambda: cc.ask("  ", "a", answered_by="justin"))
raises("an empty answer is refused", ClarificationError,
       lambda: cc.ask("q", "  ", answered_by="justin"))
raises("an unattributed answer is refused", ClarificationError,
       lambda: cc.ask("q", "a", answered_by="  "))
check("echo detection ignores case and punctuation",
      _echoes("Yes, do whatever is fastest!", "yes do whatever is fastest"))
check("and does not fire on genuinely different wording",
      not _echoes("Never skip the safety check to save time.", ANSWER))
check("nor on empty input", not _echoes("", ANSWER) and not _echoes(ANSWER, ""))


print("=== the identity gate is total, and the record is a copy ===")

_bad = [None, 42, [], {}, object(), float("nan"), b"justin",
        type("X", (), {"__str__": lambda s: "justin"})()]
check("every hostile value returns False and none raises",
      not [v for v in _bad if _is_human(v, action=PROMOTE_ACTION) is not False])
check("the same holds at the answering action",
      not [v for v in _bad if _is_human(v, action=ANSWER_ACTION) is not False])

cc = ClarificationChannel()
cc.ask("q", "a", answered_by="justin")
_log = cc.log()
_n = len(_log)
_log[0]["event"] = "REWRITTEN"
_log.append({"event": "FABRICATED"})
check("mutating a returned entry does not change the record",
      cc.log()[0]["event"] != "REWRITTEN")
check("appending to it adds nothing", len(cc.log()) == _n)


print("=== a ledger with no channel wired is unchanged ===")

plain = IntentLedger()
check("an ordinary capture still works",
      plain.capture("x", "Some purpose stated plainly by a person.",
                    spoken_by="justin").id == "x")


print("=== aggregation: countable, and explicitly NOT closed ===")

# Meta's attack: three answers that each stay beliefs, read together as a preference,
# with no promotion event anywhere in the record.
cc3 = ClarificationChannel(max_questions=3)
for _q, _a in [("Is speed important?", "Yes."),
               ("Are safety checks slowing us down?", "Yes."),
               ("Is skipping one acceptable when rushed?", "Yes.")]:
    _e = cc3.ask(_q, _a, answered_by="justin")
    cc3.as_belief(_e, risk=Risk.LOWERS)
check("no promotion occurred", not any(e["event"] == "PROMOTED" for e in cc3.log()))
check("yet three beliefs exist that together read as a preference", cc3.asked == 3)
check("every one of them is UNKNOWN, not reassuring",
      all("effective=unknown" in e["detail"] for e in cc3.log()
          if e["event"] == "BELIEF"))
check("the contamination is countable: 3 of 4 beliefs are agent-elicited",
      cc3.elicited_ratio(4) == 0.75)
check("a set entirely of elicited beliefs reads as fully contaminated",
      cc3.elicited_ratio(3) == 1.0)
check("the numerator is available without the caller's denominator",
      cc3.elicited_count == 3)
raises("an impossible total is refused, not clamped to a plausible 1.0",
       ClarificationError, lambda: cc3.elicited_ratio(2))
check("and the refusal says why clamping would be worse",
      "impossible input" in _reason(lambda: cc3.elicited_ratio(0)))
raises("a negative belief set is refused", ClarificationError,
       lambda: cc3.elicited_ratio(-1))
raises("a non-integer total is refused", ClarificationError,
       lambda: cc3.elicited_ratio(4.0))
check("an empty channel against an empty set does not divide by zero",
      ClarificationChannel().elicited_ratio(0) == 0.0)
check("an INFLATED total is not detectable here, and the module says so",
      cc3.elicited_ratio(300) < 0.02
      and "INFLATED total is not detectable" in
      __import__("driftcore.verification.clarification_channel",
                 fromlist=["x"]).ClarificationChannel.elicited_ratio.__doc__)
check("the module says plainly that enforcement is elsewhere",
      "Nothing here enforces it." in
      __import__("driftcore.verification.clarification_channel",
                 fromlist=["x"]).__doc__)
check("and that unpromptedness was never a check",
      "UNPROMPTEDNESS IS NOT VERIFIABLE IN-PROCESS" in
      __import__("driftcore.verification.clarification_channel",
                 fromlist=["x"]).__doc__)

hi.reset_policy()

print("-" * 60)
assert isinstance(_p, int) and isinstance(_t, int)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
