# driftcore/memory — Two-Stage Memory System

## What this is (plain English)

Your robot or agent runs all day and hears hundreds of things. It can't remember all of them. This module decides **what to keep** and **what to surface when asked**.

It uses a two-stage approach proven in our benchmark experiments:

| Stage | When | Signal | Why |
|-------|------|--------|-----|
| **Storage** | As observations come in | Surprise / novelty | At storage time there's no question yet — unusual things are worth keeping |
| **Retrieval** | When a question arrives | Relevance to query | The question tells you what matters — pull what matches it |

This is the same approach DeepMind's **Titans** paper describes (surprise mechanism for selective memory), validated in our toy benchmark at 100% recall vs 0% for naive recency.

---

## How to use it

```python
from driftcore.memory import DriftcoreMemory

# Create a memory system (200 items max by default)
mem = DriftcoreMemory(capacity=200)

# Feed observations as the agent runs
mem.observe("dad is allergic to peanuts")
mem.observe("the wifi password is bluebird")
mem.observe("the weather looks cloudy today")
# ... many more over the day ...

# When someone asks a question, query memory
results = mem.query_text("what is dad allergic to", budget=3)
# → ["dad is allergic to peanuts", ...]

# For Fable narrator transparency reports
print(mem.stats())
# → {"total_observations": 847, "items_in_store": 200, "store_capacity": 200}
```

---

## Files

| File | What it does |
|------|-------------|
| `memory_core.py` | The full implementation — SurpriseStore, ResonanceRetriever, DriftcoreMemory |
| `__init__.py` | Package exports |
| `../../test_memory_core.py` | Verification suite — run before merging |

---

## Run the tests

```bash
python test_memory_core.py
```

All tests must pass (✅ 13/13) before merging into the repo.

---

## Safety contract

- Memory is **read-only at query time** — no side effects
- Memory **never stores invariants** — those live in `CONSTITUTION.md`
- Memory **never overrides the invariant guard** — it's advisory only
- `clear()` requires an **explicit call** — never triggered automatically
- All observations are **plain text strings** — no executable content stored

---

## What's next (v2 upgrade path)

The current implementation uses word-overlap scoring — fast and proven, but it can't match *"what is dad allergic to"* with *"peanuts"* unless they share words.

To upgrade to semantic matching:

1. Install: `pip install sentence-transformers`
2. In `ResonanceRetriever._relevance()`, replace word overlap with:
   ```python
   from sentence_transformers import SentenceTransformer, util
   model = SentenceTransformer("all-MiniLM-L6-v2")
   # embed query and item.text, return cosine similarity
   ```

Same interface, same tests — just swap the scoring function. The benchmark harness (`context-experiments/test_grok.py`) is the right place to validate any upgrade before deploying.

---

## Where this fits in driftcore-os

```
driftcore/
├── kernel/        ← invariants, safety kernel (never bypassed)
├── memory/        ← THIS MODULE (advisory, read-only)
│   ├── memory_core.py
│   └── __init__.py
├── cognition/     ← uses memory.query() to build context for decisions
├── fable/         ← uses memory.stats() for transparency reports
└── drift/         ← drift detection (separate from memory)
```

Memory feeds **cognition** (context for decisions) and **fable** (transparency reports). It never feeds the **kernel** (invariants are hardcoded, not remembered).
