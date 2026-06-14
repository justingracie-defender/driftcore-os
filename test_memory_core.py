"""
test_memory_core.py — VERIFY THE MEMORY MODULE WORKS
=====================================================

Run this after adding driftcore/memory/ to the repo.
All tests must pass before merging.

    python test_memory_core.py

Tests cover:
  - Basic store and retrieve
  - Noise resistance (needle in haystack)
  - Safety contract (clear requires explicit call)
  - Stats reporting for Fable narrator
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.memory import DriftcoreMemory

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append(condition)


print("=" * 56)
print("  DRIFTCORE MEMORY MODULE — VERIFICATION SUITE")
print("=" * 56)


# ── TEST 1: Basic store and retrieve ──────────────────────────
print("\n  [1] Basic store and retrieve")
mem = DriftcoreMemory()
mem.observe("the robot's name is Pip")
mem.observe("Emma's math test is on Friday")
mem.observe("the wifi password is bluebird")

results1 = mem.query_text("what is the robot's name", budget=3)
check("robot name retrieved", any("pip" in r.lower() for r in results1))

results2 = mem.query_text("what is the wifi password", budget=3)
check("wifi password retrieved", any("bluebird" in r.lower() for r in results2))

results3 = mem.query_text("when is emma's math test", budget=3)
check("math test date retrieved", any("friday" in r.lower() for r in results3))


# ── TEST 2: Noise resistance ───────────────────────────────────
print("\n  [2] Noise resistance (needle in haystack)")
mem2 = DriftcoreMemory()

NOISE = [
    "the weather looks cloudy today", "someone watched a movie",
    "the kitchen light is on", "a car drove past outside",
    "the plant needs watering soon", "the news mentioned the economy",
    "a bird sang this morning", "the floor was just cleaned",
    "dinner might be pasta tonight", "the clock ticks quietly",
]
# Add 40 noise items
for i in range(40):
    mem2.observe(NOISE[i % len(NOISE)])

# Bury the needle
mem2.observe("dad is allergic to peanuts")

# Add 20 more noise items after
for i in range(20):
    mem2.observe(NOISE[i % len(NOISE)])

results_noise = mem2.query_text("what is dad allergic to", budget=5)
check("needle found in 61-item haystack",
      any("peanut" in r.lower() for r in results_noise))


# ── TEST 3: Stats reporting ────────────────────────────────────
print("\n  [3] Stats reporting (for Fable narrator)")
stats = mem2.stats()
check("stats returns total_observations", "total_observations" in stats)
check("stats returns items_in_store", "items_in_store" in stats)
check("observation count is accurate", stats["total_observations"] == 61)


# ── TEST 4: MemoryItem has expected fields ─────────────────────
print("\n  [4] MemoryItem structure")
mem3 = DriftcoreMemory()
item = mem3.observe("the dog's medicine is at 6pm", source="family", tags=["health"])
check("item has text", item.text == "the dog's medicine is at 6pm")
check("item has surprise_score", isinstance(item.surprise_score, float))
check("item has timestamp", item.timestamp > 0)
check("item has source", item.source == "family")
check("item has tags", "health" in item.tags)
check("item.age_seconds() works", item.age_seconds() >= 0)


# ── TEST 5: Clear is explicit ──────────────────────────────────
print("\n  [5] Clear behaviour")
mem4 = DriftcoreMemory()
mem4.observe("something important")
mem4.clear()
check("clear wipes store", mem4.stats()["items_in_store"] == 0)
check("clear resets observation count", mem4.stats()["total_observations"] == 0)


# ── RESULTS ───────────────────────────────────────────────────
print("\n" + "=" * 56)
passed = sum(results)
total = len(results)
print(f"  {passed}/{total} tests passed")
if passed == total:
    print(f"  {PASS} All tests pass. Safe to merge.")
else:
    print(f"  {FAIL} Some tests failed. Do not merge until fixed.")
print("=" * 56)

if passed < total:
    sys.exit(1)
