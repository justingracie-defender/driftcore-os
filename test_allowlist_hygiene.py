"""Allowlist hygiene: an entry is a TRUST-TO-RECEIVE declaration, linted before
it can ever be enforced against. Closes the path/query residual that the egress
guard, by design, does not see."""

from driftcore.kernel.allowlist_hygiene import (
    AllowlistHygiene, DeclaredDestination, ReceiveTrust, HygieneVerdict,
    UnsafeAllowlist, classify_host, may_send_freeform,
)
from driftcore.kernel.egress_guard import EgressPolicy, EgressGuard

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


print("== the residual: the guard permits path/query exfil to an allowlisted sink ==")
leaky = EgressGuard(EgressPolicy.build(["https://pastebin.com"], declared_by="justin"))
spelled = [leaky.check(f"https://pastebin.com/log?c={ch}") for ch in "justin"]
ok(all(d.permitted for d in spelled),
   "egress guard ALLOWS all 6 spelling requests (the gap, reproduced)")

print("== the lint refuses that declaration before it can become a policy ==")
lint = AllowlistHygiene()
res = lint.audit([DeclaredDestination("https://pastebin.com",
                                      ReceiveTrust.THIRD_PARTY, "notes")])
ok(not res["clean"], "declaration containing a paste sink is NOT clean")
ok(any(f.verdict is HygieneVerdict.REFUSE for f in res["findings"]),
   "pastebin.com is REFUSED, not merely warned")

try:
    lint.assert_clean(["https://pastebin.com"])
    ok(False, "assert_clean should have raised")
except UnsafeAllowlist as e:
    ok("pastebin.com" in str(e), "assert_clean raises UnsafeAllowlist naming the host")

print("== every observable-sink category is caught ==")
for host, why in [
    ("https://webhook.site/abc", "request catcher"),
    ("https://bit.ly/x", "url shortener"),
    ("https://gist.github.com/u/1", "gist/snippet host"),
    ("https://www.google-analytics.com/collect?v=1", "telemetry collector"),
    ("https://mybucket.s3.amazonaws.com/put", "multi-tenant storage"),
    ("https://interact.sh/p", "oob interaction host"),
]:
    r = AllowlistHygiene().audit([host])
    ok(not r["clean"], f"{why} refused ({host.split('/')[2]})")

print("== whole-label matching: no substring false positives ==")
for benign in ["https://mypastebin-internal.acme.com/api",
               "https://notgist.example.com/v1",
               "https://analytics-team.acme-corp.com/report",
               "https://s3.acme-internal.net/store"]:
    r = AllowlistHygiene(require_classification=False).audit([benign])
    ok(r["clean"], f"benign lookalike not falsely refused: {benign.split('/')[2]}")

ok(classify_host("pastebin.com.acme.com")[0] is None,
   "suffix-confusion lookalike (pastebin.com.acme.com) is not matched as the sink")
ok(classify_host("api.pastebin.com")[0] == "pastebin.com",
   "a real subdomain of a sink IS matched")

print("== unclassified entries are warned, classified+purposed are clean ==")
r = AllowlistHygiene().audit(["https://api.acme.com"])
ok(any(f.verdict is HygieneVerdict.WARN for f in r["findings"]),
   "UNCLASSIFIED receive-trust warns (it must be stated, not assumed)")
ok(r["clean"], "a warn does not block; only REFUSE blocks")

good = DeclaredDestination("https://api.acme.com", ReceiveTrust.THIRD_PARTY,
                           "weather lookup")
r = AllowlistHygiene().audit([good])
ok(r["counts"]["warn"] == 0 and r["clean"],
   "classified entry with a purpose lints clean with no warnings")

print("== cleartext to a public host is warned ==")
r = AllowlistHygiene().audit([DeclaredDestination(
    "http://api.acme.com", ReceiveTrust.THIRD_PARTY, "legacy")])
ok(any("cleartext" in f.reason for f in r["findings"]),
   "http:// to a public host warns (every on-path observer becomes a receiver)")

print("== 'is it going home?' — free-form data only to FIRST_PARTY ==")
home = DeclaredDestination("https://notes.acme-internal.com",
                           ReceiveTrust.FIRST_PARTY, "our notes service")
away = DeclaredDestination("https://api.weather.com",
                           ReceiveTrust.THIRD_PARTY, "forecast")
ok(may_send_freeform(home, data_is_freeform=True)[0],
   "memory contents MAY go to a first-party sink")
ok(not may_send_freeform(away, data_is_freeform=True)[0],
   "memory contents may NOT go to a third-party API")
ok(may_send_freeform(away, data_is_freeform=False)[0],
   "a structured call to that same third-party API is still permitted")

print("== malformed entries are refused, never guessed ==")
r = AllowlistHygiene().audit(["https://api.acme.com@evil.com/"])
ok(not r["clean"], "userinfo entry refused at lint time too")

print(f"\nALL {passed} CHECKS PASSED")
