"""
test_ai_bus.py — first tests this module has ever had.

# CLAIMS: driftcore/network/ai_bus.py:broadcast-is-recorded
# CLAIMS: driftcore/network/ai_bus.py:history-not-editable

Both lines of the original two-line docstring were false. "Everything is recorded" —
`broadcast()` recorded nothing. "Nothing passes silently" — `get_history()` handed
back the live message dicts, so a reader could rewrite the record.

# CLAIMS: driftcore/network/ai_bus.py:history-copy-is-deep
"""

import threading

from driftcore.network.ai_bus import AIBus

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


print("=== a broadcast is recorded like any other traffic ===")

b = AIBus()
before = len(b.messages)
out = b.broadcast({"from": "planner", "body": "halt"}, ["arm", "vision"])
check("one record per delivery", len(b.messages) - before == 2)
check("and that is what was returned", len(out) == 2)
check("each names its recipient",
      sorted(m["_to"] for m in b.get_history()) == ["arm", "vision"])
check("each is marked as a broadcast",
      all(m["_kind"] == "broadcast" for m in b.get_history()))
check("all deliveries share one timestamp",
      len({m["_sent"] for m in b.get_history()}) == 1)

b2 = AIBus()
b2.broadcast({"from": "planner", "body": "x"})
check("a broadcast with no recipient list is still recorded once",
      len(b2.messages) == 1 and b2.messages[0]["_to"] is None)


b = AIBus()
out = b.broadcast({"from": "p", "body": "x"}, ["a", "a", "b", "a"])
check("duplicate recipients are collapsed", len(out) == 2)
check("order is preserved", [m["_to"] for m in out] == ["a", "b"])
check("and the record is not inflated", len(b.messages) == 2)


print("=== broadcast SENDS; it does not replay history ===")

b = AIBus()
b.send({"from": "arm", "body": "original"})
b.broadcast({"from": "planner", "body": "new"}, ["arm"])
hist = b.get_history()
check("the earlier message is unchanged",
      any(m["body"] == "original" and m["_kind"] == "send" for m in hist))
check("and the broadcast is its own record, not a mutated copy",
      any(m["body"] == "new" and m["_kind"] == "broadcast" for m in hist))
check("recipients selects who it goes TO, not whose messages get replayed",
      all(m["from"] == "planner" for m in hist if m["_kind"] == "broadcast"))


print("=== the record cannot be edited through the accessor ===")

b = AIBus()
b.send({"from": "a", "body": "x", "nested": {"k": "v"}})
h = b.get_history()
h[0]["body"] = "REWRITTEN"
h[0]["nested"]["k"] = "REWRITTEN"
h.append({"from": "ghost"})
check("reassigning a returned field does not change the record",
      b.messages[0]["body"] == "x")
check("mutating a NESTED value does not either",
      b.messages[0]["nested"]["k"] == "v")
check("appending to the returned list adds nothing",
      len(b.messages) == 1)

msg = {"from": "a", "body": "x"}
b2 = AIBus()
b2.send(msg)
msg["body"] = "CHANGED_AFTER_SENDING"
check("mutating the dict you sent does not rewrite what was recorded",
      b2.messages[0]["body"] == "x")


print("=== every message names its sender ===")

b = AIBus()
raises("no sender is refused", ValueError, lambda: b.send({"body": "x"}))
raises("a None sender is refused", ValueError, lambda: b.send({"from": None}))
raises("an empty sender is refused", ValueError, lambda: b.send({"from": "  "}))
raises("a non-string sender is refused", ValueError, lambda: b.send({"from": 7}))
raises("a non-dict message is refused", TypeError, lambda: b.send("hello"))
raises("a broadcast with no sender is refused", ValueError,
       lambda: b.broadcast({"body": "x"}))
check("and none of them were recorded", b.messages == [])

raises("an EMPTY recipients list is refused rather than meaning 'everyone'",
       ValueError, lambda: b.broadcast({"from": "a"}, []))


print("=== the timestamp is the bus's, not the caller's ===")

b = AIBus()
b.send({"from": "a", "_sent": "1999-01-01T00:00:00"})
check("a caller-supplied _sent is overwritten",
      not b.messages[0]["_sent"].startswith("1999"))
check("and it carries a UTC offset", b.messages[0]["_sent"].endswith("+00:00"))


print("=== history filtering ===")

b = AIBus()
b.send({"from": "a", "body": "1"})
b.send({"from": "b", "body": "2"})
b.send({"from": "a", "body": "3"})
check("filtering by sender returns only theirs", len(b.get_history("a")) == 2)
check("an unknown sender returns nothing", b.get_history("nobody") == [])
check("no filter returns everything", len(b.get_history()) == 3)


print("=== the bus is bounded and concurrent sends are not lost ===")

b = AIBus(max_messages=50)
for i in range(200):
    b.send({"from": "a", "n": i})
check("the message list is capped", len(b.messages) == 50)
check("the dropped count is kept", b.dropped_messages == 150)
check("the OLDEST are dropped, not the newest", b.messages[-1]["n"] == 199)

b = AIBus()


def hammer():
    for _ in range(300):
        b.send({"from": "a", "body": "x"})


ths = [threading.Thread(target=hammer) for _ in range(4)]
for t in ths:
    t.start()
for t in ths:
    t.join()
check("no messages lost under concurrency",
      len(b.messages) + b.dropped_messages == 1200)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
